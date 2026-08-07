console.log("TLS Lab asset loaded");

if (window.location.pathname === "/heavy.html") {
  fetch("/assets/img-small.bin", { cache: "no-store" });
  fetch("/assets/img-large.bin", { cache: "no-store" });
}
