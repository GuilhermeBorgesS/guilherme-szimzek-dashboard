TESTES DE FALHA — EVIDÊNCIAS

Caso 1: retorno sem cookie temporário

Preparação: iniciado o login em uma janela comum, copiada a URL de autorização e colada em uma janela privativa (sem o cookie __Host-oauth-tx), completando o login lá.

Pedido enviado: GET /oauth/callback/google?code=[REMOVIDO]&state=[REMOVIDO] (sem o cookie __Host-oauth-tx)

Resultado esperado: HTTP 400, "Transação ausente", nenhuma sessão criada.

Resultado observado: HTTP 400 com a mensagem "Transação ausente" — conforme esperado. Nenhuma sessão foi criada.

Caso 2: state alterado

Preparação: iniciado o login, parado na página do provedor, alterado um caractere do parâmetro state na barra de endereço. Uma primeira tentativa editando a URL na tela do Google acabou completando o login normalmente — isso ocorreu porque a página do Google já mantinha a transação original internamente e não reenviou o valor editado. Refeito o teste de forma direta: acessando manualmente a rota de callback do próprio site com um state deliberadamente incorreto (mesmo cookie de transação válido).

Pedido enviado: GET /oauth/callback/google?code=[REMOVIDO]&state=[ALTERADO]

Resultado esperado: HTTP 400, "Transação inválida", troca de código não realizada.

Resultado observado: HTTP 400 com a mensagem "Transação inválida" — conforme esperado, confirmando que o servidor rejeita corretamente um state que não corresponde ao valor salvo no D1.

Caso 3: reutilização da transação

Preparação: concluído um login com sucesso, localizada a requisição de retorno (/oauth/callback/google?code=...&state=...) no painel Network e reaberta a mesma URL.

Pedido enviado: GET /oauth/callback/google?code=[REMOVIDO]&state=[REMOVIDO] (repetido)

Resultado esperado: HTTP 400, transação já removida do D1, falha na repetição.

Resultado observado: Erro "Falha na autenticação" — a repetição da requisição de retorno não criou nova sessão nem manteve o login. O resultado de segurança desejado foi confirmado: a mesma URL de retorno não pode ser reaproveitada para autenticar novamente.

Caso 4: sessão expirada

Preparação: criada uma sessão de teste, depois executado no console D1: UPDATE sessions SET expires_at = 0;

Pedido enviado: GET /api/me

Resultado esperado: HTTP 401.

Resultado observado: HTTP 401 — a página voltou automaticamente para a tela de login ("Nenhuma sessão neste navegador."), confirmando que uma sessão com expires_at no passado é tratada como inválida.

Caso 5: origem inválida na saída

Preparação: com sessão válida em https://guilherme-szimzek-dashboard.pages.dev/, aberta outra origem (https://youtube.com) e executado no console do navegador um fetch para https://guilherme-szimzek-dashboard.pages.dev/oauth/logout com credentials: "include".

Pedido enviado: POST /oauth/logout (Origin diferente de PUBLIC_BASE_URL)

Resultado esperado: HTTP 403, sessão original permanece válida.

Resultado observado: HTTP 403 confirmado no console do navegador ("Status code: 403"), além do próprio navegador bloquear a leitura da resposta por política de CORS ("CORS Missing Allow Origin"). A sessão original em URL_BASE permaneceu válida.

Caso 6: reutilização do cookie revogado

Preparação: copiado o valor do cookie __Host-session enquanto a sessão ainda estava ativa. Em seguida, executado o logout e restaurado manualmente o mesmo valor de cookie pelo DevTools.

Pedido enviado: GET /api/me (com cookie de sessão já revogado)

Resultado esperado: HTTP 401, pois a linha foi removida do D1.

Resultado observado: HTTP 401, "Não autorizado" — o cookie revogado não restaurou a sessão, confirmando que a linha correspondente foi efetivamente removida do D1 no momento do logout.
