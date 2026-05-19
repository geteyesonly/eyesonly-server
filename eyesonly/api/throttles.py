from django.conf import settings
from rest_framework.settings import api_settings
from rest_framework.throttling import ScopedRateThrottle

# make tests work
class SettingsAwareScopedRateThrottle(ScopedRateThrottle):
    def get_rate(self):
        rest_framework_settings = getattr(settings, 'REST_FRAMEWORK', {})
        throttle_rates = rest_framework_settings.get('DEFAULT_THROTTLE_RATES', {})

        if self.scope in throttle_rates:
            return throttle_rates[self.scope]

        return api_settings.DEFAULT_THROTTLE_RATES.get(self.scope)