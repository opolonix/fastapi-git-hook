from fastapi import FastAPI, Request, HTTPException
import subprocess, os, hmac, hashlib, importlib, re, string, random

class GitHook:
    def __init__(
        self, 
        app: FastAPI,
        path: str = "/git",
        domain: str = "localhost",
        secret: str = "secret.py"
    ):
        """
            :app - обьект роутера
            :path - ручка для хуков
            :domain - внешний адрес, по которому будет лежать обработчик
            :secret - файл, в котором будет сохранен секрет
        """
        app.router.add_route(
            path,
            self.github_webhook,
            methods="POST",
            name="git hook",
            include_in_schema=False # скрывает роутер из общей схемы
        )
        self.schema = '# Шаблон для секрета гитхаба\n\nGIT_SECRET = "{secret}"\nPATH = "{path}"'
        clear_domain = re.search(r'^(?:https?:\/\/)?(?:www\.)?([^\/]+)', domain, re.I).group(1)
        full_path = f"http://{clear_domain}{path}"

        if os.path.exists(secret):
            f = importlib.__import__('.'.join(secret.split('.')[:-1]))

            self.git_secret: str = getattr(f, "GIT_SECRET")
            self.rout_path: str = getattr(f, "PATH")

            if self.rout_path != full_path:
                file = open(secret, 'w+', encoding='utf-8')
                filled = self.schema.format(
                    secret=self.git_secret,
                    path=full_path
                )
                file.write(filled)
                file.close()
        else:
            self.git_secret = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(64))
            self.rout_path = full_path
            filled = self.schema.format(
                secret=self.git_secret,
                path=full_path
            )
            file = open(secret, 'w+', encoding='utf-8')
            file.write(filled)
            file.close()

    async def github_webhook(self, request: Request):
        signature = request.headers.get("X-Hub-Signature")

        if signature is None:
            raise HTTPException(status_code=403, detail="Signature header required")

        body = await request.body()

        hash_algorithm, signature_hash = signature.split("=", 1)
        hmac_hash = hmac.new(self.git_secret.encode(), body, hashlib.sha1).hexdigest()
        if not hmac.compare_digest(signature_hash, hmac_hash):
            raise HTTPException(status_code=403, detail="Invalid signature")

        subprocess.run("git pull", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

app = FastAPI()

GitHook(app)