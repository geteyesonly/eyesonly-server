from django.apps import AppConfig


class EyesonlyConfig(AppConfig):
    name = 'eyesonly'

    def ready(self):
        import eyesonly.signals  # noqa: F401
