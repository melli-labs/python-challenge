# 👩‍💻 Melli - Python Challenge 

Hi 👋, I am Melli!

Currently, our `code` is broken :/ Can you help me to fix it?

## Challenge

The `melli.py` contains a simple backend written in FastAPI, which does not pass our tests ❌. The challenge is to make the tests pass without modifying the `test_melli.py` file ✔️!

Clone 👯 the repository and try to get the tests running in your local environment. If you manage to make all tests pass, we would love to interview you 😍! Therefore, create a pull request, which triggers a GitHub action, verifying that you solved the challenge correctly 🏆.

### Setup

Install Python >3.9 and the dependencies with [poetry](https://python-poetry.org/):

```python
poetry install
```

Start the application:

```python
poetry run uvicorn melli:app --reload
```

Open `http://localhost:8080` in a webbrowser. Melli will greet you and give you some initial information.

After you finish a task, try if it passes the test:

```python
poetry run pytest -xsk task1
```

When you finished all tests, this should run without an error message:

```python
poetry run pytest -m "not bonus"
```

Or, if you solved the bonus task:

```python
poetry run pytest
```

Now you can go ahead and create a pull request!
