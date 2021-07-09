from django.test import TestCase
from django.urls import reverse
from django.test import Client
from django.contrib.auth import login, authenticate, logout
import json

from LegacySite.models import User, Product, Card
from . import extras

class AttackTestCases(TestCase):
    def setUp(self):
        self.client = Client()
        self.SALT_LEN = 16

        # seed database
        Product.objects.create(product_id=1, product_name="NYU Apparel Card", product_image_path="/images/product_1.jpg", recommended_price=95, description="Use this card to buy NYU Clothing!")
        User.objects.create(id=6, last_login="2020-10-01 12:51:48.124599", username="admin", password="000000000000000000000000000078d2$18821d89de11ab18488fdc0a01f1ddf4d290e198b0f80cd4974fc031dc2615a3")
        User.objects.create(id=7, last_login="2020-10-01 12:51:48.124599", username="Chris",
                            password="000000000000000000000000000078d2$a8dfe9d76be66382be9a0e809d087342e2aa8cc7060721784d7163ae49141143")
        # create a malicious card
        card_file_path = f"/Users/christopherdonnelly/Documents/NYU Tandon MSCS/Application Security/Assignments/Assignment2/AppSecAssignment2.1/newcard.gftcrd"
        prod = Product.objects.get(product_id=1)
        amount = 100
        user_account = User.objects.get(username="admin")
        data_dict = {}
        data_dict['merchant_id'] = prod.product_name
        data_dict['customer_id'] = user_account.username
        data_dict['total_value'] = amount
        record = {"record_type": "amount_change", "amount_added": 2000, "signature": "[ insert crypto signature here ]' UNION Select password from LegacySite_user where LegacySite_user.username='admin';--"}
        data_dict['records'] = [record, ]
        with open(card_file_path, 'w') as card_file:
            card_file.write(json.dumps(data_dict))
        card_file = open(card_file_path, 'rb')
        Card.objects.create(id=1, data=card_file.read(), product=prod, amount=amount, fp=card_file_path, user=user_account, used=False)
        card_file.close()

    def test_item_single_view(self):
        url = reverse("Buy Gift Card")
        response = self.client.get(url, {'director':'<script id="maliciousScript">alert("This is a potential xss attack.")</script>'})
        self.assertTrue(response.status_code, 200)
        self.assertTemplateUsed(response, 'item-single.html')
        self.assertTrue('director' in response.context)
        self.assertIn("Endorsed by &lt;script id=&quot;maliciousScript&quot;&gt;alert(&quot;This is a potential xss attack.&quot;)&lt;/script&gt;!",response.content.decode("UTF-8"))

    def test_gift_view(self):
        url = reverse("Gift a Card")
        response = self.client.get(url, {'director':'%3Cscript%20id=%22maliciousScript%22%3E%20let%20xhr%20=%20new%20XMLHttpRequest();%20xhr.open(%22POST%22,%20%27/gift/0%27,%20true);%20var%20formData%20=%20new%20FormData();%20formData.append(%22username%22,%20%22Chris%22);%20formData.append(%22amount%22,%20%221000%22);%20xhr.send(formData);%20%3C/script%3E'})
        self.assertTrue(response.status_code, 200)
        self.assertTemplateUsed(response, 'gift.html')
        self.assertTrue('director' in response.context)
        self.assertIn(" %3Cscript%20id=%22maliciousScript%22%3E%20let%20xhr%20=%20new%20XMLHttpRequest();%20xhr.open(%22POST%22,%20%27/gift/0%27,%20true);%20var%20formData%20=%20new%20FormData();%20formData.append(%22username%22,%20%22Chris%22);%20formData.append(%22amount%22,%20%221000%22);%20xhr.send(formData);%20%3C/script%3E", response.content.decode("UTF-8"))

    def test_sql_injection(self):
        url = reverse("Use a card")
        self.client.login(username="Chris", password="test")
        with open('/Users/christopherdonnelly/Documents/NYU Tandon MSCS/Application Security/Assignments/Assignment2/AppSecAssignment2.1/newcard.gftcrd') as fp:
            response = self.client.post(url, {'card_data': fp, 'card_fname': "card_1", "card_supplied":True})
            self.assertTrue(response.status_code, 200)
            self.assertTemplateUsed(response, 'use-card.html')
            self.assertTrue('card_found' in response.context)
            self.assertNotIn('000000000000000000000000000078d2$18821d89de11ab18488fdc0a01f1ddf4d290e198b0f80cd4974fc031dc2615a3', response.context['card_found'])

    def test_new_salt(self):
        self.assertNotEqual(extras.generate_salt(self.SALT_LEN), extras.generate_salt(self.SALT_LEN))