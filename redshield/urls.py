from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('scanner.urls')),
    path('api/reports/', include('reports.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Health check
from django.http import JsonResponse
def health(request): return JsonResponse({"status":"ok","version":"2.5.0"})
urlpatterns += [path('health/', health)]
