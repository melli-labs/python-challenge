import pytest
from httpx import AsyncClient

from emilia import app


@pytest.fixture()
async def async_client():
    async_client = AsyncClient(app=app, base_url="http://test")
    yield async_client
    await async_client.aclose()


@pytest.mark.asyncio
async def test_task1(async_client):
    response = await async_client.get("/task1/greet/Jasmin")
    assert response.status_code == 200
    assert response.json() == "Hallo Jasmin, ich bin Emilia."

    response = await async_client.get("/task1/greet/Stefan", params={"language": "en"})
    assert response.status_code == 200
    assert response.json() == "Hello Stefan, I am Emilia."

    response = await async_client.get("/task1/greet/Hans", params={"language": "es"})
    assert response.status_code == 200
    assert response.json() == "Hola Hans, soy Emilia."

    response = await async_client.get("/task1/greet/Ben", params={"language": "ita"})
    assert response.status_code == 200
    assert response.json() == f"Hallo Ben, leider spreche ich nicht 'ita'!"


@pytest.mark.depends(on=["test_task1"])
def test_task1_success_message():
    print(
        " 🎉 Congratulations! You solved the first task."
        " Go to `/task2` to solve the next one."
    )


@pytest.mark.asyncio
async def test_task2(async_client):
    data = {"company_name": "Emilia", "is_future_unicorn": True}

    response = await async_client.post("/task2/camelize", json=data)
    assert response.status_code == 200
    assert response.json() == {
        "companyName": "Emilia",
        "isFutureUnicorn": True,
    }


@pytest.mark.depends(on=["test_task2"])
def test_task2_success_message():
    print(
        " 🏃 Wow, keep going! Let's see if you solve the next one too."
        " You can find it at `/task3`."
    )


@pytest.mark.asyncio
class TestTask3:
    async def test_call_friend(self, async_client):
        response = await async_client.post(
            "/task3/action",
            json={"username": "Matthias", "action": "Call my friend Sahar."},
        )
        assert response.status_code == 200
        assert response.json() == {
            "message": "🤙 Calling Sahar ...",
        }

        response = await async_client.post(
            "/task3/action",
            json={"username": "Matthias", "action": "Can you call Hans?"},
        )
        assert response.status_code == 200
        assert response.json() == {
            "message": "🤙 Calling Hans ...",
        }

        response = await async_client.post(
            "/task3/action",
            json={
                "username": "Matthias",
                "action": "I haven't spoken to Franziska in a long time. Can you call her?",
            },
        )
        assert response.status_code == 200
        assert response.json() == {
            "message": "🤙 Calling Franziska ...",
        }

        response = await async_client.post(
            "/task3/action",
            json={
                "username": "Stefan",
                "action": "Can you call Ben for me?",
            },
        )
        assert response.status_code == 200
        assert response.json() == {
            "message": "🤙 Calling Ben ...",
        }

    async def test_call_unknown(self, async_client):
        response = await async_client.post(
            "/task3/action",
            json={"username": "Stefan", "action": "Call my friend Christian."},
        )
        assert response.status_code == 200
        assert response.json() == {
            "message": "Stefan, I can't find this person in your contacts.",
        }

    async def test_reminder(self, async_client):
        response = await async_client.post(
            "/task3/action",
            json={
                "username": "Stefan",
                "action": "Remind me to book the theater tickets.",
            },
        )
        assert response.status_code == 200
        assert response.json() == {
            "message": "🔔 Alright, I will remind you!",
        }

    async def test_timer(self, async_client):
        response = await async_client.post(
            "/task3/action",
            json={"username": "Matthias", "action": "Set a timer for eight minutes!"},
        )
        assert response.status_code == 200
        assert response.json() == {
            "message": "⏰ Alright, the timer is set!",
        }

    async def test_unknown_action(self, async_client):
        response = await async_client.post(
            "/task3/action",
            json={"username": "Stefan", "action": "What is the meaning of life?"},
        )
        assert response.status_code == 200
        assert response.json() == {
            "message": "👀 Sorry , but I can't help with that!",
        }

    async def test_unknown_user(self, async_client):
        response = await async_client.post(
            "/task3/action",
            json={"username": "Felix", "action": "Call my friend Leo."},
        )
        assert response.status_code == 200
        assert response.json() == {
            "message": "Hi Felix, I don't know you yet. But I would love to meet you!",
        }

        response = await async_client.post(
            "/task3/action",
            json={
                "username": "Ben",
                "action": "Hey Emilia, remind me to rewrite our PHP backend in Rust 🦀!",
            },
        )
        assert response.status_code == 200
        assert response.json() == {
            "message": "Hi Ben, I don't know you yet. But I would love to meet you!",
        }


@pytest.mark.depends(on=["TestTask3"])
def test_task3_success_message():
    print(
        " ⭐ This was really hard, congratulations! You're awesome 🙌!"
        " If you really wanna impress us, there is an optional bonus task at `/task4`."
        " But if you're short on time you can already create a pull request at"
        " https://github.com/mit-emilia/hiring!"
    )


@pytest.mark.bonus
@pytest.mark.asyncio
class TestTask4:
    stefan = {"username": "stefan", "password": "decent-espresso-by-john-buckmann"}
    felix = {"username": "felix", "password": "elm>javascript"}

    @pytest.fixture()
    async def token_stefan(self, async_client):
        response = await async_client.post("/task4/token", data=self.stefan)
        assert response.status_code == 200
        return response.json()

    @pytest.fixture()
    async def token_felix(self, async_client):
        response = await async_client.post("/task4/token", data=self.felix)
        assert response.status_code == 200
        return response.json()

    async def test_login_registered_user(self, token_stefan, token_felix):
        for token in token_stefan, token_felix:
            assert isinstance(token, dict)
            assert "token_type" in token and "access_token" in token

    async def test_login_registered_user_wrong_password(self, async_client):
        stefan_wrong_password = self.stefan | {"password": "wrong_password"}
        response = await async_client.post("/task4/token", data=stefan_wrong_password)
        assert response.status_code == 401
        assert response.json() == {"detail": "Incorrect username or password"}

    async def test_login_unregistered_user(self, async_client):
        response = await async_client.post(
            "/task4/token", data={"username": "hacker", "password": "123456"}
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Incorrect username or password"}

    async def test_read_own_secret(self, async_client, token_stefan):
        response = await async_client.get(
            "/task4/users/stefan/secret",
            headers={"Authorization": f"Bearer {token_stefan['access_token']}"},
        )
        assert response.status_code == 200
        assert response.json() == "I love pressure-profiled espresso ☕!"

    async def test_read_other_user_secret(self, async_client, token_felix):
        response = await async_client.get(
            "/task4/users/stefan/secret",
            headers={"Authorization": f"Bearer {token_felix['access_token']}"},
        )
        assert response.status_code == 403
        assert response.json() == {"detail": "Don't spy on other user!"}


@pytest.mark.depends(on=["TestTask4"])
def test_task4_success_message():
    print(
        " 🤩 Amazing! This is really impressive. Here is your prize 🏆!"
        " We would love to get in touch with you 💯. Therefore, create"
        " a pull request at https://github.com/mit-emilia/hiring!"
    )
