// ==========================================
// 1. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (ХРАНЕНИЕ ДАННЫХ)
// ==========================================

/**
 * Загружает товары. Сначала из localStorage, если пусто - из дефолтного массива.
 */
function loadProducts() {
  const saved = localStorage.getItem('topiary_products');
  if (saved) {
    try {
      return JSON.parse(saved);
    } catch (e) {
      console.error('Ошибка чтения localStorage, используем дефолт', e);
    }
  }

  // Дефолтные товары (база данных по умолчанию)
  return [
    {
      id: 1,
      name: "Топиар «Шар»",
      desc: "Классический шар из самшита, диаметр 60 см.",
      price: 4500,
      img: "https://via.placeholder.com/300x300?text=Shar"
    },
    {
      id: 2,
      name: "Топиар «Спираль»",
      desc: "Спиральная форма из туи, высота 120 см.",
      price: 7200,
      img: "https://via.placeholder.com/300x300?text=Spiral"
    },
    {
      id: 3,
      name: "Топиар «Медведь»",
      desc: "Декоративная фигура медведя из искусственной травы, высота 90 см.",
      price: 18000,
      img: "https://via.placeholder.com/300x300?text=Bear"
    }
  ];
}

/**
 * Сохраняет текущий массив товаров в localStorage
 */
function saveProducts() {
  localStorage.setItem('topiary_products', JSON.stringify(products));
}

// ==========================================
// 2. ИНИЦИАЛИЗАЦИЯ ДАННЫХ И ПРАВ
// ==========================================

// Глобальная переменная товаров (теперь она всегда актуальна)
let products = loadProducts();

// Проверка режима админа (параметр ?admin=true в URL)
const isAdmin = new URLSearchParams(window.location.search).has('admin');

// ==========================================
// 3. ОТРИСОВКА СТРАНИЦЫ И КАТАЛОГА
// ==========================================

function renderPage() {
  // Логика отображения панели админа
  const editControls = document.getElementById("edit-controls");
  if (editControls) {
    editControls.style.display = isAdmin ? "block" : "none";
  }
}

function renderCatalog() {
  const grid = document.getElementById("catalog-grid");
  if (!grid) return;

  grid.innerHTML = ""; // Очищаем сетку перед перерисовкой

  if (products.length === 0) {
    grid.innerHTML = "<p style='text-align:center; color:#666;'>Каталог пуст. Добавьте товары через панель админа.</p>";
    return;
  }

  products.forEach(p => {
    // Формируем HTML картинки
    let imgHtml = "";
    if (p.img) {
      imgHtml = `<img src="${p.img}" alt="${p.name}" loading="lazy">`;
    } else {
      imgHtml = `<div style="height:200px; background:#eee; display:flex; align-items:center; justify-content:center; color:#999;">Нет фото</div>`;
    }

    // ВАЖНО: Используем обратные кавычки `` ` `` для шаблона!
    // Именно здесь происходит подстановка ${p.name}, а не вывод текста
    const cardHtml = `
      <div class="product-card">
        ${imgHtml}
        <h3>${p.name}</h3>
        <p>${p.desc}</p>
        <div class="price">${p.price.toLocaleString()} ₽</div>
        
        <!-- Кнопки видны ТОЛЬКО если включен режим админа -->
        ${isAdmin ? `<button class="btn-edit-product" data-id="${p.id}">✏️ Редактировать</button>` : ""}
        ${isAdmin ? `<button class="btn-delete-product" data-id="${p.id}" style="color:red; background:none; border:none; cursor:pointer; margin-left:5px;">🗑️ Удалить</button>` : ""}
      </div>
    `;

    // Вставляем через innerHTML (НЕ textContent!)
    grid.insertAdjacentHTML('beforeend', cardHtml);

    // Вешаем обработчики событий на кнопки (только для админа)
    if (isAdmin) {
      // Находим кнопки внутри только что созданной карточки
      const lastCard = grid.lastElementChild;
      const editBtn = lastCard.querySelector(".btn-edit-product");
      const delBtn = lastCard.querySelector(".btn-delete-product");

      if (editBtn) {
        editBtn.addEventListener("click", () => openProductForm(p));
      }
      if (delBtn) {
        delBtn.addEventListener("click", () => {
          if(confirm('Удалить товар?')) {
            deleteProduct(p.id);
          }
        });
      }
    }
  });
}

// ==========================================
// 4. ЛОГИКА АДМИН-ПАНЕЛИ (ДОБАВЛЕНИЕ/РЕДАКТИРОВАНИЕ)
// ==========================================

function openProductForm(product = null) {
  const form = document.getElementById("product-edit-form");
  const title = document.getElementById("edit-form-title");
  const idInput = document.getElementById("product-id");
  const nameInput = document.getElementById("product-name");
  const descInput = document.getElementById("product-desc");
  const priceInput = document.getElementById("product-price");
  const imageInput = document.getElementById("product-image");

  form.style.display = "block";

  if (product) {
    title.textContent = "Редактировать товар";
    idInput.value = product.id;
    nameInput.value = product.name;
    descInput.value = product.desc;
    priceInput.value = product.price;
    imageInput.value = product.img || "";
  } else {
    title.textContent = "Добавить товар";
    idInput.value = "";
    nameInput.value = "";
    descInput.value = "";
    priceInput.value = "";
    imageInput.value = "";
  }
}

function saveProduct() {
  const id = document.getElementById("product-id").value;
  const name = document.getElementById("product-name").value.trim();
  const desc = document.getElementById("product-desc").value.trim();
  const price = parseFloat(document.getElementById("product-price").value);
  const img = document.getElementById("product-image").value.trim();

  if (!name || isNaN(price) || price <= 0) {
    alert("Проверьте название и цену (цена должна быть числом > 0).");
    return;
  }

  if (id) {
    // РЕДАКТИРОВАНИЕ
    const idx = products.findIndex(p => p.id == id);
    if (idx !== -1) {
      products[idx] = { ...products[idx], name, desc, price, img };
    }
  } else {
    // ДОБАВЛЕНИЕ НОВОГО
    products.push({
      id: Date.now(), // Уникальный ID
      name,
      desc,
      price,
      img
    });
  }

  saveProducts(); // <--- САМОЕ ВАЖНОЕ: сохраняем изменения в память браузера
  renderCatalog(); // Перерисовываем каталог
  closeProductForm();
  alert("Товар сохранён!");
}

function deleteProduct(id) {
  products = products.filter(p => p.id !== id);
  saveProducts(); // Сохраняем изменения после удаления
  renderCatalog();
}

function closeProductForm() {
  document.getElementById("product-edit-form").style.display = "none";
}

// ==========================================
// 5. ИНИЦИАЛИЗАЦИЯ ПРИ ЗАГРУЗКЕ СТРАНИЦЫ
// ==========================================

document.addEventListener("DOMContentLoaded", () => {
  renderPage();
  renderCatalog();

  // --- Обработчики кнопок страницы (заголовки и т.д.) ---
  const toggleEditBtn = document.getElementById("toggle-edit-btn");
  const savePageBtn = document.getElementById("save-page-btn");
  const cancelPageEditBtn = document.getElementById("cancel-page-edit-btn");

  if (toggleEditBtn) toggleEditBtn.addEventListener("click", togglePageEditMode);
  if (savePageBtn) savePageBtn.addEventListener("click", savePage);
  if (cancelPageEditBtn) cancelPageEditBtn.addEventListener("click", togglePageEditMode);

  // --- Обработчики кнопок каталога ---
  const toggleCatalogEditBtn = document.getElementById("toggle-catalog-edit-btn");
  const saveProductBtn = document.getElementById("save-product-btn");
  const cancelProductEditBtn = document.getElementById("cancel-product-edit-btn");

  if (toggleCatalogEditBtn) {
    toggleCatalogEditBtn.addEventListener("click", () => {
      openProductForm(null);
    });
  }
  
  if (saveProductBtn) {
    saveProductBtn.addEventListener("click", saveProduct);
  }
  
  if (cancelProductEditBtn) {
    cancelProductEditBtn.addEventListener("click", closeProductForm);
  }
});

// --- Вспомогательные функции для редактирования главной страницы (оставлены для совместимости) ---
function togglePageEditMode() {
  const form = document.getElementById("page-edit-form");
  if (!form) return;
  
  const isVisible = form.style.display === "block";
  
  if (!isVisible) {
    document.getElementById("title-input").value = pageData.title;
    document.getElementById("intro-input").value = pageData.intro;
    form.style.display = "block";
  } else {
    form.style.display = "none";
  }
}

function savePage() {
  pageData.title = document.getElementById("title-input").value.trim();
  pageData.intro = document.getElementById("intro-input").value.trim();
  
  renderPage();
  alert("Страница обновлена!");
  togglePageEditMode();
}

// Данные для главной страницы
const pageData = {
  title: "Садовые топиарии ручной работы",
  intro: "Создайте уникальный ландшафт: долговечные топиарии из натуральных и искусственных материалов."
};
