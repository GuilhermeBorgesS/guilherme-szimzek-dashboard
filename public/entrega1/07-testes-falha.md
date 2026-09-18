# Testes de falha — evidências

Para cada caso, preencha os quatro campos com o que foi de fato observado.
Substitua qualquer valor sensível (cookie, code, state, code_challenge) por [REMOVIDO].

## Caso 1: retorno sem cookie temporário

- **Preparação:** iniciar login em uma janela comum, copiar a URL de autorização,
  colar em janela privativa (sem o cookie `__Host-oauth-tx`) e concluir o login lá.
- **Pedido enviado:** GET /oauth/callback/{provider}?code=[REMOVIDO]&state=[REMOVIDO]
  (sem o cookie `__Host-oauth-tx`)
- **Resultado esperado:** HTTP 400, "Transação ausente", nenhuma sessão criada.
- **Resultado observado:** _preencher_

## Caso 2: state alterado

- **Preparação:** iniciar login, parar na página do provedor, alterar um caractere
  do parâmetro `state` na barra de endereço antes de concluir.
- **Pedido enviado:** GET /oauth/callback/{provider}?code=[REMOVIDO]&state=[ALTERADO]
- **Resultado esperado:** HTTP 400, "Transação inválida", troca de código não realizada.
- **Resultado observado:** _preencher_

## Caso 3: reutilização da transação

- **Preparação:** concluir um login com sucesso, localizar a requisição de retorno
  no painel Network e reabrir a mesma URL (Copy URL).
- **Pedido enviado:** GET /oauth/callback/{provider}?code=[REMOVIDO]&state=[REMOVIDO]
  (repetido)
- **Resultado esperado:** HTTP 400, transação já removida do D1, falha na repetição.
- **Resultado observado:** _preencher_

## Caso 4: sessão expirada

- **Preparação:** criar uma sessão de teste, depois executar no console D1:
  `UPDATE sessions SET expires_at = 0;`
- **Pedido enviado:** GET /api/me
- **Resultado esperado:** HTTP 401.
- **Resultado observado:** _preencher_

## Caso 5: origem inválida na saída

- **Preparação:** com sessão válida em URL_BASE, abrir outra origem (ex.:
  https://example.com) e executar no console do navegador um fetch para
  URL_BASE/oauth/logout com credentials: "include".
- **Pedido enviado:** POST /oauth/logout (Origin diferente de PUBLIC_BASE_URL)
- **Resultado esperado:** HTTP 403, sessão original permanece válida.
- **Resultado observado:** _preencher_

## Caso 6: reutilização do cookie revogado

- **Preparação:** copiar temporariamente o valor do cookie `__Host-session`,
  executar logout, tentar restaurar o mesmo valor de cookie e consultar /api/me.
  Apagar a cópia do valor imediatamente após o teste.
- **Pedido enviado:** GET /api/me (com cookie de sessão já revogado)
- **Resultado esperado:** HTTP 401, pois a linha foi removida do D1.
- **Resultado observado:** _preencher_
