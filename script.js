// The shared server catalogue replaces the old per-browser localStorage editor.
function productCard(product) {
  const card = document.createElement('article');
  card.className = 'product-card';
  const image = document.createElement('img');
  image.src = product.img;
  image.alt = product.name;
  image.loading = 'lazy';
  image.addEventListener('error', () => { image.src = '/assets/catalog-placeholder.svg'; }, { once: true });
  const name = document.createElement('h3'); name.textContent = product.name;
  const description = document.createElement('p'); description.textContent = product.desc;
  const price = document.createElement('div'); price.className = 'price';
  price.textContent = new Intl.NumberFormat('ru-RU', { style: 'currency', currency: 'RUB', maximumFractionDigits: 2 }).format(product.price);
  card.append(image, name, description, price);
  return card;
}

async function refreshCatalog() {
  const grid = document.querySelector('#catalog-grid');
  if (!grid) return;
  try {
    const response = await fetch('/api/catalog', { cache: 'no-store', credentials: 'same-origin', signal: AbortSignal.timeout(10000) });
    if (!response.ok) throw new Error();
    const result = await response.json();
    if (!Array.isArray(result.products)) throw new Error();
    grid.replaceChildren(...result.products.map(productCard));
    if (!result.products.length) {
      const empty = document.createElement('p'); empty.textContent = 'В каталоге пока нет опубликованных изделий.'; grid.append(empty);
    }
  } catch {
    const message = document.createElement('p'); message.textContent = 'Не удалось загрузить каталог. ';
    const retry = document.createElement('button'); retry.type = 'button'; retry.textContent = 'Попробовать снова';
    retry.addEventListener('click', refreshCatalog); grid.replaceChildren(message, retry);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  refreshCatalog();
  const burger = document.querySelector('.burger');
  burger?.addEventListener('click', () => {
    const nav = document.querySelector('header nav');
    const open = nav.classList.toggle('mobile-open');
    burger.setAttribute('aria-expanded', String(open));
  });
});
window.addEventListener('pageshow', event => { if (event.persisted) refreshCatalog(); });
