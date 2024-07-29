from sony.settings import AUTHENTICATION_BACKENDS
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.test.utils import override_settings


# @override_settings(AUTHENTICATION_BACKENDS=('api.backends.EmailAuthBackend',))
class ApiViewTestCases(TestCase):
    """
    Test cases for testing out logic in api app
    """
    fixtures = ["points.json", "configs.json", "user.json"]

    def setUp(self) -> None:
        self.user = User.objects.get(id=14)

    def test_points_view_put_method(self):
        """
        Test case for testing out points put method
        """
        self.client.login(username='scottmicheal@test.com',
                          password='@New_Scot#2021')
        point_data = {
            "data": "invoice:A123454521,name:WH-1000XM4 Wireless Noise Cancelling Headphones,price:1148.99,name:WH-1000XM4 Wireless Noise Cancelling Headphones,price:1148.99,name:WH-1000XM4 Wireless Noise Cancelling Headphones,price:1148.99,name:WH-1000XM4 Wireless Noise Cancelling Headphones,price:1148.99,name:WH-1000XM4 Wireless Noise Cancelling Headphones,price:1148.99,name:WH-1000XM4 Wireless Noise Cancelling Headphones,price:1148.99"
        }
        response = self.client.put(reverse(
            'api_points'), data=point_data, content_type="application/json")
        self.assertEqual(response.status_code, 200,
                         msg="Didn't receive success code in response")
        self.assertContains(response, "status")
        self.assertEqual(response.json()['status'], "Success")
