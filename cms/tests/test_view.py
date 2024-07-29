from django.test import TestCase, SimpleTestCase
from django.urls import reverse
from rest_framework import response


class CmsTestCases(TestCase):
    """
    Test case for transaction api
    """
    fixtures = ["user.json", "transaction.json", "configs.json"]

    def test_transaction_get_method(self):
        """
        Testing GET Method
        """

        response = self.client.get(reverse("cms_tran_details"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'Success')
        self.assertContains(response, "data")

    def test_app_config_get_method(self):
        response = self.client.get(reverse("cms_app_config"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'status')
        self.assertEqual(response.json()['status'], 'Success')
        self.assertContains(response, 'data')

    def test_app_config_put_method_success(self):
        response = self.client.put(reverse('cms_app_config'), data={
                                   "loyalty_percent": 5}, content_type="application/json")
        self.assertEqual(response.status_code, 200,
                         msg="Did not receive success code")
        self.assertContains(response, 'status')
        self.assertEqual(response.json()['status'], 'Success')
        self.assertContains(response, 'message')
        self.assertEqual(
            response.json()['message'], 'Configuration updated on the app')

    def test_app_config_put_method_failure(self):
        response = self.client.put(reverse('cms_app_config'), data={
                                   "loyalty_percent": "hello"}, content_type="application/json")
        self.assertEqual(response.status_code, 500,
                         msg="Did not receive internal server error code")
