import setuptools

with open('VERSION.txt', 'r') as f:
    version = f.read().strip()

setuptools.setup(
    name="odoo10-addons-akretion-factur-x-validator",
    description="Meta package for akretion-factur-x-validator Odoo addons",
    version=version,
    install_requires=[
        'odoo10-addon-facturx_validator',
    ],
    classifiers=[
        'Programming Language :: Python',
        'Framework :: Odoo',
        'Framework :: Odoo :: 10.0',
    ]
)
