const STORAGE_KEY = "church-inventory-items-v1";
const categories = { audio:"음향", lighting:"조명", video:"영상", instrument:"악기", electrical:"전기", general:"일반비품" };
const statuses = { normal:"정상", repair_needed:"수리 필요", repairing:"수리 중", disposed:"폐기" };
const sampleItems = [
  { id:"sample-1", name:"무선 마이크", category:"audio", status:"normal", quantity:4, location:"본당 음향실", manufacturer:"Shure", modelName:"BLX24R", serialNumber:"", purchaseDate:"2024-03-15", purchasePrice:1200000, memo:"주일예배용", photo:"", createdAt:1 },
  { id:"sample-2", name:"LED 파 조명", category:"lighting", status:"repair_needed", quantity:2, location:"본당 무대 뒤", manufacturer:"LITEPUTER", modelName:"PAR-180", serialNumber:"", purchaseDate:"2023-08-10", purchasePrice:480000, memo:"1대 밝기 점검 필요", photo:"", createdAt:2 },
  { id:"sample-3", name:"디지털 피아노", category:"instrument", status:"normal", quantity:1, location:"찬양대실", manufacturer:"Yamaha", modelName:"P-125", serialNumber:"", purchaseDate:"2022-12-01", purchasePrice:850000, memo:"", photo:"", createdAt:3 }
];

let items = loadItems();
let currentPhoto = "";
const $ = (selector) => document.querySelector(selector);

function loadItems() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    return saved === null ? sampleItems : JSON.parse(saved);
  } catch { return sampleItems; }
}
function saveItems() { localStorage.setItem(STORAGE_KEY, JSON.stringify(items)); }
function escapeHtml(value="") { const el=document.createElement("div"); el.textContent=String(value); return el.innerHTML; }
function formatPrice(value) { return value === "" || value == null ? "-" : `${Number(value).toLocaleString("ko-KR")}원`; }

function fillOptions() {
  $("#category").innerHTML = Object.entries(categories).map(([v,l])=>`<option value="${v}">${l}</option>`).join("");
  $("#status").innerHTML = Object.entries(statuses).map(([v,l])=>`<option value="${v}">${l}</option>`).join("");
  $("#categoryFilter").innerHTML += Object.entries(categories).map(([v,l])=>`<option value="${v}">${l}</option>`).join("");
  $("#statusFilter").innerHTML += Object.entries(statuses).map(([v,l])=>`<option value="${v}">${l}</option>`).join("");
  $("#categoryTabs").innerHTML = `<button class="active" data-category="">전체</button>` + Object.entries(categories).map(([v,l])=>`<button data-category="${v}">${l}</button>`).join("");
}

function render() {
  const query = $("#searchInput").value.trim().toLowerCase();
  const category = $("#categoryFilter").value;
  const status = $("#statusFilter").value;
  const filtered = items.filter(item => {
    const haystack = [item.name,item.manufacturer,item.modelName,item.serialNumber,item.location,item.memo].join(" ").toLowerCase();
    return (!query || haystack.includes(query)) && (!category || item.category===category) && (!status || item.status===status);
  }).sort((a,b)=>(b.createdAt||0)-(a.createdAt||0));
  $("#itemGrid").innerHTML = filtered.map(item => `
    <article class="item-card">
      <div class="item-image">${item.photo ? `<img src="${item.photo}" alt="${escapeHtml(item.name)} 사진">` : `<span class="placeholder" aria-label="사진 없음">＋</span>`}</div>
      <div class="item-content">
        <div class="item-topline"><h3>${escapeHtml(item.name)}</h3><span class="badge status-${item.status}">${statuses[item.status]||item.status}</span></div>
        <p class="item-model">${escapeHtml([item.manufacturer,item.modelName].filter(Boolean).join(" · ") || categories[item.category])}</p>
        <div class="item-details"><span>보관 위치</span><strong>${escapeHtml(item.location)}</strong><span>수량</span><strong>${Number(item.quantity).toLocaleString()}개</strong>${item.purchasePrice ? `<span>구입 가격</span><strong>${formatPrice(item.purchasePrice)}</strong>`:""}</div>
        <div class="card-actions"><button type="button" data-edit="${item.id}">수정</button><button type="button" class="delete-button" data-delete="${item.id}" aria-label="${escapeHtml(item.name)} 삭제">삭제</button></div>
      </div>
    </article>`).join("");
  $("#emptyState").hidden = filtered.length > 0;
  $("#resultCount").textContent = `총 ${filtered.length}개의 물품`;
  $("#totalKinds").innerHTML = `${items.length}<small>종</small>`;
  $("#totalQuantity").innerHTML = `${items.reduce((sum,i)=>sum+Number(i.quantity||0),0).toLocaleString()}<small>개</small>`;
  $("#attentionCount").innerHTML = `${items.filter(i=>["repair_needed","repairing"].includes(i.status)).length}<small>종</small>`;
  const locations=[...new Set(items.map(i=>i.location).filter(Boolean))];
  $("#locationSuggestions").innerHTML=locations.map(v=>`<option value="${escapeHtml(v)}"></option>`).join("");
}

function openForm(item=null) {
  $("#itemForm").reset(); currentPhoto=item?.photo||""; $("#itemId").value=item?.id||"";
  $("#formTitle").textContent=item?"물품 정보 수정":"새 물품 등록"; $("#saveButton").textContent=item?"변경 내용 저장":"물품 저장";
  if(item) ["name","category","status","quantity","location","manufacturer","modelName","serialNumber","purchaseDate","purchasePrice","memo"].forEach(key=>$("#"+key).value=item[key]??"");
  updatePhotoPreview(); $("#itemModal").hidden=false; document.body.classList.add("modal-open"); setTimeout(()=>$("#name").focus(),50);
}
function closeForm(){ $("#itemModal").hidden=true;document.body.classList.remove("modal-open"); }
function updatePhotoPreview(){ const box=$("#photoPreview");box.hidden=!currentPhoto;if(currentPhoto) box.querySelector("img").src=currentPhoto; }
function showToast(message){const toast=$("#toast");toast.textContent=message;toast.classList.add("show");clearTimeout(showToast.timer);showToast.timer=setTimeout(()=>toast.classList.remove("show"),2200);}

function resizePhoto(file) {
  return new Promise((resolve,reject)=>{ const reader=new FileReader();reader.onerror=reject;reader.onload=()=>{const img=new Image();img.onerror=reject;img.onload=()=>{const max=900;const scale=Math.min(1,max/Math.max(img.width,img.height));const canvas=document.createElement("canvas");canvas.width=Math.round(img.width*scale);canvas.height=Math.round(img.height*scale);canvas.getContext("2d").drawImage(img,0,0,canvas.width,canvas.height);resolve(canvas.toDataURL("image/jpeg",.78));};img.src=reader.result;};reader.readAsDataURL(file); });
}

fillOptions(); render();
$("#openFormButton").addEventListener("click",()=>openForm());
$("#mobileOpenFormButton").addEventListener("click",()=>openForm());
document.querySelectorAll("[data-close-modal]").forEach(el=>el.addEventListener("click",closeForm));
document.addEventListener("keydown",e=>{if(e.key==="Escape"&&!$("#itemModal").hidden)closeForm();});
["searchInput","categoryFilter","statusFilter"].forEach(id=>$("#"+id).addEventListener(id==="searchInput"?"input":"change",render));
$("#categoryTabs").addEventListener("click",e=>{const button=e.target.closest("button");if(!button)return;$("#categoryFilter").value=button.dataset.category;document.querySelectorAll("#categoryTabs button").forEach(b=>b.classList.toggle("active",b===button));render();});
$("#categoryFilter").addEventListener("change",()=>document.querySelectorAll("#categoryTabs button").forEach(b=>b.classList.toggle("active",b.dataset.category===$("#categoryFilter").value)));
$("#clearFiltersButton").addEventListener("click",()=>{$("#searchInput").value="";$("#categoryFilter").value="";$("#statusFilter").value="";document.querySelector("#categoryTabs button").click();});
$("#photo").addEventListener("change",async e=>{const file=e.target.files[0];if(!file)return;try{currentPhoto=await resizePhoto(file);updatePhotoPreview();}catch{showToast("사진을 불러오지 못했습니다.");}});
$("#removePhotoButton").addEventListener("click",()=>{currentPhoto="";$("#photo").value="";updatePhotoPreview();});
$("#itemForm").addEventListener("submit",e=>{e.preventDefault();const id=$("#itemId").value;const item={id:id||crypto.randomUUID(),photo:currentPhoto,createdAt:id?(items.find(i=>i.id===id)?.createdAt||Date.now()):Date.now()};["name","category","status","location","manufacturer","modelName","serialNumber","purchaseDate","memo"].forEach(k=>item[k]=$("#"+k).value.trim());item.quantity=Number($("#quantity").value);item.purchasePrice=$("#purchasePrice").value===""?"":Number($("#purchasePrice").value);items=id?items.map(i=>i.id===id?item:i):[...items,item];try{saveItems();render();closeForm();showToast(id?"물품 정보를 수정했습니다.":"새 물품을 등록했습니다.");}catch{showToast("브라우저 저장 공간이 부족합니다. 사진 크기를 줄여주세요.");}});
$("#itemGrid").addEventListener("click",e=>{const edit=e.target.closest("[data-edit]");const del=e.target.closest("[data-delete]");if(edit)openForm(items.find(i=>i.id===edit.dataset.edit));if(del){const item=items.find(i=>i.id===del.dataset.delete);if(item&&confirm(`‘${item.name}’ 물품을 삭제할까요?\n삭제한 내용은 되돌릴 수 없습니다.`)){items=items.filter(i=>i.id!==item.id);saveItems();render();showToast("물품을 삭제했습니다.");}}});
