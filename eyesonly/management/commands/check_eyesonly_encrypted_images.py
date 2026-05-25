from django.core.management.base import BaseCommand
from django.utils import timezone

from eyesonly.models import EncryptedImage


class Command(BaseCommand):
	help = 'Delete expired encrypted images.'

	def add_arguments(self, parser):
		parser.add_argument(
			'--dry-run',
			action='store_true',
			help='Show how many images would be deleted without deleting them.',
		)

	def handle(self, *args, **options):
		now = timezone.now()
		expired_images = EncryptedImage.objects.filter(expires_at__isnull=False, expires_at__lt=now)
		expired_count = expired_images.count()

		if options['dry_run']:
			self.stdout.write(
				self.style.WARNING(
					f'Dry run: {expired_count} expired encrypted image(s) would be deleted.'
				)
			)
			return

		deleted_count, _ = expired_images.delete()
		self.stdout.write(
			self.style.SUCCESS(
				(
					f'Deleted {expired_count} expired encrypted image(s) '
					f'({deleted_count} total row(s) including related records).'
				)
			)
		)
