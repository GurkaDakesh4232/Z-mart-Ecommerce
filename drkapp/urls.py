
from django.urls import path
from drkapp import views

urlpatterns = [
    path('',views.home,name='home'),
    path('purchase',views.purchase,name='purchase'),
    path('checkout', views.checkout, name="Checkout"),
    path('about', views.about, name="About Us"),
    path('service', views.service, name="service"),
    path('placed', views.placed, name="placed"),
    path('tracker', views.tracker, name="tracker"),
    path('handlerequest', views.handlerequest, name="HandleRequest"),
    

    
]
