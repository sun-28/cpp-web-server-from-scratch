document.addEventListener('DOMContentLoaded', () => {
    const todoForm = document.getElementById('add-todo-form');
    const todoInput = document.getElementById('todo-input');
    const todoList = document.getElementById('todo-list');

    const apiUrl = './cgi-bin/todo.py'; // Our CGI endpoint

    // --- Core API Request Function ---
    async function apiRequest(method, data = null) {
        try {
            const options = {
                method: method,
                headers: {
                    // Important: Tell the server we're sending/expecting JSON
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
            };
            if (data) {
                options.body = JSON.stringify(data);
            }

            const response = await fetch(apiUrl, options);

            if (!response.ok) {
                // Try to get error message from server response body
                let errorMsg = `HTTP error! status: ${response.status}`;
                try {
                    const errorData = await response.json();
                    errorMsg = errorData.error || errorMsg;
                } catch (e) { /* Ignore if response body isn't valid JSON */ }
                throw new Error(errorMsg);
            }
            return await response.json(); // Assuming server always responds with JSON

        } catch (error) {
            console.error('API Request Failed:', error);
            alert(`Error communicating with server: ${error.message}`);
            return null; // Indicate failure
        }
    }


    // --- Render To-Do List ---
    function renderTodos(todos) {
        todoList.innerHTML = ''; // Clear existing list or loading message

        if (!todos || todos.length === 0) {
            const emptyLi = document.createElement('li');
            emptyLi.textContent = 'No tasks yet! Add one above.';
            emptyLi.style.textAlign = 'center';
            emptyLi.style.fontStyle = 'italic';
            emptyLi.style.color = '#6c757d';
            todoList.appendChild(emptyLi);
            return;
        }

        todos.forEach(todo => {
            const li = document.createElement('li');
            li.dataset.id = todo.id; // Store id on the element
            li.classList.toggle('done', todo.done); // Add 'done' class if applicable

            const taskContent = document.createElement('div');
            taskContent.classList.add('task-content');

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.checked = todo.done;
            checkbox.addEventListener('change', () => toggleTodo(todo.id));

            const textSpan = document.createElement('span');
            textSpan.classList.add('task-text');
            textSpan.textContent = todo.text;

            taskContent.appendChild(checkbox);
            taskContent.appendChild(textSpan);

            const deleteBtn = document.createElement('button');
            deleteBtn.textContent = 'Delete';
            deleteBtn.classList.add('delete-btn');
            deleteBtn.addEventListener('click', () => deleteTodo(todo.id));

            li.appendChild(taskContent);
            li.appendChild(deleteBtn);
            todoList.appendChild(li);
        });
    }

    // --- Fetch Initial Todos ---
    async function fetchTodos() {
        const data = await apiRequest('POST', { action: 'get' }); // Using POST for consistency
        if (data && data.todos) {
             renderTodos(data.todos);
        } else {
            // Handle case where server didn't return expected data
             renderTodos([]); // Render empty state
        }
    }

    // --- Add Todo ---
    async function addTodo(text) {
        const data = await apiRequest('POST', { action: 'add', text: text });
        if (data && data.todos) {
            renderTodos(data.todos); // Re-render the whole list
            todoInput.value = ''; // Clear input field
        }
    }

    // --- Delete Todo ---
    async function deleteTodo(id) {
        // Optional: Confirm before deleting
        if (!confirm('Are you sure you want to delete this task?')) {
            return;
        }
        const data = await apiRequest('POST', { action: 'delete', id: id });
        if (data && data.todos) {
            renderTodos(data.todos);
        }
    }

    // --- Toggle Todo Done/Undone ---
    async function toggleTodo(id) {
        const data = await apiRequest('POST', { action: 'toggle', id: id });
        if (data && data.todos) {
             renderTodos(data.todos); // Re-render needed to update class/checkbox
        } else {
            // If request failed, maybe revert checkbox state visually?
             console.error("Toggle failed, list might be out of sync");
        }
    }

    // --- Event Listeners ---
    todoForm.addEventListener('submit', (e) => {
        e.preventDefault(); // Prevent traditional form submission (page reload)
        const text = todoInput.value.trim();
        if (text) {
            addTodo(text);
        }
    });

    // --- Initial Load ---
    fetchTodos();

}); // End DOMContentLoaded