fetch("/api/me", { credentials: "same-origin" })
  .then((response) => (response.ok ? response.json() : null))
  .then((user) => {
    const status = document.getElementById("status");
    const logoutForm = document.getElementById("logout-form");
    const loginOptions = document.querySelector(".login-options");
    const dashboardLink = document.getElementById("dashboard-link");

    if (user) {
      status.textContent = `Sessão de ${user.email ?? user.displayName}.`;
      logoutForm.hidden = false;
      if (loginOptions) loginOptions.hidden = true;
      if (dashboardLink) dashboardLink.hidden = false;
    } else {
      status.textContent = "Nenhuma sessão neste navegador.";
      logoutForm.hidden = true;
      if (loginOptions) loginOptions.hidden = false;
      if (dashboardLink) dashboardLink.hidden = true;
    }
  })
  .catch(() => {
    document.getElementById("status").textContent = "Não foi possível consultar a sessão.";
  });
