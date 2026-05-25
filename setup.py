from setuptools import find_packages, setup


setup(
	name='django-eyesonly',
	version='0.1.3',
	description='Eyes Only Django application',
	packages=find_packages(include=['eyesonly', 'eyesonly.*']),
	include_package_data=True,
	install_requires=[
		'djangorestframework>=3.15,<4',
		'djangorestframework-simplejwt>=5.3,<6',
		'cryptography>=48',
		'PyYAML>=6,<7',
		'uritemplate>=4,<5',
		'inflection>=0.5,<1',
		'pynacl>=1.5.0,<2',
	],
)