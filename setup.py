from setuptools import find_packages, setup


setup(
	name='django-eyesonly',
	version='0.1.0',
	description='Eyes Only Django application',
	packages=find_packages(include=['eyesonly', 'eyesonly.*']),
	install_requires=[
		'djangorestframework>=3.15,<4',
		'djangorestframework-simplejwt>=5.3,<6',
		'cryptography>=46,<47',
		'PyYAML>=6,<7',
		'uritemplate>=4,<5',
		'inflection>=0.5,<1',
		'pynacl>=1.5.0,<2',
	],
)