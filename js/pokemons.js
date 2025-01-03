
    const baseUrl = "http://localhost:8080";
    let pokemons = [];
    let filteredPokemons = [];
    let pokemonsPerPage = 6;
    let currentPage = 1;
    let sortAttribute = null;
    let sortDirection = null;

    async function fetchPokemons() {
    const response = await fetch(`${baseUrl}/pokemons`);
    pokemons = await response.json();
    filteredPokemons = pokemons;
    displayPokemons();
    displayPagination();
    populateFilter();
    numPerPage();
}

    function showNumPokemons(num) {
    pokemonsPerPage = num;
    currentPage = 1;
    displayPokemons();
    displayPagination();
}

    function filterByType(type) {
    if (type === "All") {
    filteredPokemons = pokemons;
} else {
    filteredPokemons = pokemons.filter(pokemon => pokemon.type === type);
}
    currentPage = 1;
    displayPokemons();
    displayPagination();
}

    function sortPokemons(attribute, direction) {
    sortAttribute = attribute;
    sortDirection = direction;

    filteredPokemons.sort((a, b) => {
    if (a[attribute] < b[attribute]) return direction === 'asc' ? -1 : 1;
    if (a[attribute] > b[attribute]) return direction === 'asc' ? 1 : -1;
    return 0;
});

    currentPage = 1;
    displayPokemons();
}

    function displayPokemons() {
    const container = document.querySelector(".pokemon-container");
    container.innerHTML = "";

    const startIndex = (currentPage - 1) * pokemonsPerPage;
    const endIndex = startIndex + pokemonsPerPage;
    const pokemonsToDisplay = filteredPokemons.slice(startIndex, endIndex);

    pokemonsToDisplay.forEach(pokemon => {
    const card = document.createElement("div");
    card.className = "pokemon-card";
    card.innerHTML = `
                    <h3>${pokemon.name}</h3>
                    <img src="${pokemon.path}" alt="${pokemon.name}">
                    <p><strong>Type:</strong> ${pokemon.type}</p>
                    <p>${pokemon.desc}</p>
                `;
    container.appendChild(card);
});
}

    function displayPagination() {
    const paginationContainer = document.querySelector(".pagination");
    paginationContainer.innerHTML = "";

    const totalPages = Math.ceil(filteredPokemons.length / pokemonsPerPage);

    for (let i = 1; i <= totalPages; i++) {
    const button = document.createElement("button");
    button.innerText = i;
    button.onclick = () => {
    currentPage = i;
    displayPokemons();
};
    paginationContainer.appendChild(button);
}
}

    function populateFilter() {
    const filterContainer = document.querySelector("#pokemonTypeFilter");
    const types = ["All", "Grass", "Fire", "Water", "Electric", "Fairy", "Normal", "Fighting", "Ghost", "Rock", "Psychic", "Bug", "Dark", "Steel", "Ice", "Dragon"];

    types.forEach(type => {
    const option = document.createElement("option");
    option.value = type;
    option.innerText = type;
    filterContainer.appendChild(option);
});
}

    function numPerPage() {
    const numContainer = document.querySelector("#pokemonNum");
    const nums = [6, 12, 18, 24];
    nums.forEach(num => {
    const option = document.createElement("option");
    option.value = num.toString();
    option.innerText = num.toString();
    numContainer.appendChild(option);
});
}

    window.onload = fetchPokemons;
