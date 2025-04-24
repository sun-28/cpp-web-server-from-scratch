#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import html
import traceback # Import traceback

# --- Configuration ---
DATA_FILE = os.path.join(os.path.dirname(__file__), '..', 'todos.json')

# --- Helper Functions ---

# ADD DEBUG PRINT AT THE VERY START
print("DEBUG: todo.py script started", file=sys.stderr) # Print to stderr

def log_stderr(message):
    """Helper to print debug messages to stderr."""
    print(f"DEBUG: {message}", file=sys.stderr, flush=True) # Flush immediately

def load_todos():
    log_stderr("Attempting to load todos...")
    try:
        if not os.path.exists(DATA_FILE):
            log_stderr(f"Data file {DATA_FILE} not found, returning empty list.")
            return []
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            log_stderr("Todos loaded successfully.")
            return data if isinstance(data, list) else []
    except Exception as e:
        log_stderr(f"!!! ERROR loading data: {e}")
        traceback.print_exc(file=sys.stderr) # Print full traceback to stderr
        return []

def save_todos(todos):
    log_stderr("Attempting to save todos...")
    try:
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(todos, f, indent=2)
        log_stderr("Todos saved successfully.")
        return True
    except Exception as e:
        log_stderr(f"!!! ERROR saving data: {e}")
        traceback.print_exc(file=sys.stderr)
        return False

def generate_id():
    return int(time.time() * 1000)

def send_json_response(data, status_code=200):
    log_stderr(f"Sending JSON response (status {status_code})...")
    # Print headers first
    header1 = f"Status: {status_code} OK\r\n"
    header2 = "Content-Type: application/json\r\n"
    blank_line = "\r\n" # The crucial separator

    print(header1, end='') # Use end='' to avoid extra newline from print
    print(header2, end='')
    print(blank_line, end='') # Print the blank line explicitly

    # Print JSON body
    json_body = json.dumps(data)
    print(json_body) # Normal print adds trailing newline, which is fine for the body

    # sys.stdout.flush() # Still keep commented out for now
    log_stderr(f"Sent Headers:\n{header1}{header2}{blank_line}--- End Headers ---") # Log exactly what was sent
    log_stderr(f"Sent JSON body: {json_body[:100]}...")

def send_error_response(message, status_code=400):
    log_stderr(f"!!! Sending ERROR response (status {status_code}): {message}")
    send_json_response({"error": message}, status_code)

# --- Main CGI Logic ---
def main():
    log_stderr("--- main() started ---")
    request_data = {}
    request_method = os.environ.get("REQUEST_METHOD", "GET")
    log_stderr(f"Request Method: {request_method}")

    if request_method == "POST":
        try:
            content_length = int(os.environ.get("CONTENT_LENGTH", 0))
            log_stderr(f"Content-Length: {content_length}")
            if content_length > 0:
                raw_body = sys.stdin.buffer.read(content_length)
                log_stderr(f"Raw POST body received: {raw_body[:100]}...") # Log start of raw body
                request_data = json.loads(raw_body.decode('utf-8'))
                log_stderr(f"Parsed JSON request data: {request_data}")
            else:
                 log_stderr("POST request with Content-Length 0 or missing.")

        except Exception as e:
            log_stderr(f"!!! ERROR processing POST request body: {e}")
            traceback.print_exc(file=sys.stderr)
            send_error_response(f"Invalid request body: {e}")
            return
    else:
        log_stderr("Request method is not POST.")
        # Handle GET maybe? For now, assume POST is needed for actions
        # If your initial page load fails, it might be hitting this path
        # Let's allow GET for the 'get' action
        if request_method == "GET":
             log_stderr("Allowing GET request for 'get' action implicitly.")
             request_data = {"action": "get"} # Assume get action for GET requests
        else:
             send_error_response("Method not allowed (currently only POST, or GET for initial list)", 405)
             return


    action = request_data.get("action")
    log_stderr(f"Action requested: {action}")

    if not action:
         # If JS sends POST without body/action, this might happen
         if request_method == 'POST' and content_length == 0:
             log_stderr("POST request received with no body/action. Assuming 'get'.")
             action = 'get'
         else:
             send_error_response("Missing 'action' in request data.")
             return


    todos = load_todos()
    response_data = {}

    try:
        log_stderr(f"Processing action: {action}")
        if action == "get":
            response_data = {"todos": todos}

        elif action == "add":
            # ... (rest of the add logic - add log_stderr calls inside if needed)
            text = request_data.get("text")
            if not text or not isinstance(text, str) or not text.strip():
                 send_error_response("Task text cannot be empty.")
                 return
            new_todo = { "id": generate_id(), "text": html.escape(text.strip()), "done": False }
            todos.append(new_todo)
            if save_todos(todos): response_data = {"todos": todos}
            else: send_error_response("Failed to save task.", 500); return

        elif action == "delete":
            # ... (rest of the delete logic)
            todo_id = request_data.get("id")
            if todo_id is None: send_error_response("Missing 'id' for delete."); return
            try: todo_id = int(todo_id)
            except ValueError: send_error_response("Invalid 'id' format."); return
            original_length = len(todos)
            todos = [todo for todo in todos if todo.get("id") != todo_id]
            if len(todos) == original_length: send_error_response(f"Task id {todo_id} not found.", 404); return
            if save_todos(todos): response_data = {"todos": todos}
            else: send_error_response("Failed to save after delete.", 500); return

        elif action == "toggle":
             # ... (rest of the toggle logic)
            todo_id = request_data.get("id")
            if todo_id is None: send_error_response("Missing 'id' for toggle."); return
            try: todo_id = int(todo_id)
            except ValueError: send_error_response("Invalid 'id' format."); return
            found = False
            for todo in todos:
                if todo.get("id") == todo_id:
                    todo["done"] = not todo.get("done", False); found = True; break
            if not found: send_error_response(f"Task id {todo_id} not found.", 404); return
            if save_todos(todos): response_data = {"todos": todos}
            else: send_error_response("Failed to save after toggle.", 500); return

        else:
            log_stderr(f"Unknown action received: {action}")
            send_error_response(f"Unknown action: '{action}'")
            return

        # Send successful response
        send_json_response(response_data)
        log_stderr(f"Successfully processed action '{action}' and sent response.")

    except Exception as e:
        log_stderr(f"!!! Unhandled Exception during action processing: {e}")
        traceback.print_exc(file=sys.stderr)
        send_error_response(f"An internal server error occurred: {e}", 500)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Final catch-all just in case main() itself raises an uncaught exception
        # *before* it can send an error response.
        log_stderr(f"!!! CRITICAL UNHANDLED EXCEPTION in main: {e}")
        traceback.print_exc(file=sys.stderr)
        # Try to send a desperate error response
        print("Status: 500 Internal Server Error")
        print("Content-Type: application/json")
        print()
        print(json.dumps({"error": f"Critical server error: {e}"}))
        sys.stdout.flush()
    log_stderr("--- todo.py script finished ---")