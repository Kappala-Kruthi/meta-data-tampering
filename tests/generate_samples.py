"""
tests/generate_samples.py
Generates sample media files for testing and viva demonstration.
1. sample_camera.jpg: Simulated original camera capture with EXIF tags.
2. sample_edited.jpg: Simulated edited image with altered dimensions and editor metadata.
3. sample_stripped.png: Image with clean, stripped metadata.
"""

import os
from PIL import Image, PngImagePlugin
import piexif

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "samples"))


def create_samples():
    os.makedirs(SAMPLES_DIR, exist_ok=True)

    # 1. Create simulated original camera image (800x600, blue gradient)
    img_a = Image.new("RGB", (800, 600), color=(30, 80, 160))
    path_a = os.path.join(SAMPLES_DIR, "sample_camera.jpg")

    # Build genuine EXIF structure
    zeroth_ifd = {
        piexif.ImageIFD.Make: b"Canon",
        piexif.ImageIFD.Model: b"Canon EOS 80D",
        piexif.ImageIFD.Software: b"Firmware 1.0.3",
        piexif.ImageIFD.DateTime: b"2026:10:20 14:35:10",
    }
    exif_ifd = {
        piexif.ExifIFD.DateTimeOriginal: b"2026:10:20 14:35:10",
        piexif.ExifIFD.DateTimeDigitized: b"2026:10:20 14:35:10",
        piexif.ExifIFD.ISOSpeedRatings: 100,
        piexif.ExifIFD.FNumber: (28, 10),  # f/2.8
        piexif.ExifIFD.ExposureTime: (1, 250),  # 1/250s
    }
    gps_ifd = {
        piexif.GPSIFD.GPSLatitudeRef: "N",
        piexif.GPSIFD.GPSLatitude: ((17, 1), (23, 1), (450, 10)),
        piexif.GPSIFD.GPSLongitudeRef: "E",
        piexif.GPSIFD.GPSLongitude: ((78, 1), (28, 1), (120, 10)),
    }
    exif_dict = {"0th": zeroth_ifd, "Exif": exif_ifd, "GPS": gps_ifd}
    exif_bytes = piexif.dump(exif_dict)
    img_a.save(path_a, "jpeg", exif=exif_bytes, quality=95)
    print("Created:", path_a)

    # 2. Create simulated edited image (cropped 720x540, modified tags)
    img_b = img_a.resize((720, 540))
    path_b = os.path.join(SAMPLES_DIR, "sample_edited.jpg")
    zeroth_ifd_b = {
        piexif.ImageIFD.Make: b"Canon",
        piexif.ImageIFD.Model: b"Canon EOS 80D",
        piexif.ImageIFD.Software: b"Adobe Photoshop 2024 (Windows)",
        piexif.ImageIFD.DateTime: b"2026:10:25 18:20:00",  # Modified later
    }
    exif_ifd_b = {
        piexif.ExifIFD.DateTimeOriginal: b"2026:10:20 14:35:10",
        piexif.ExifIFD.ISOSpeedRatings: 200,
    }
    # Notice: GPS is removed in sample B to simulate GPS stripping
    exif_dict_b = {"0th": zeroth_ifd_b, "Exif": exif_ifd_b}
    exif_bytes_b = piexif.dump(exif_dict_b)
    img_b.save(path_b, "jpeg", exif=exif_bytes_b, quality=85)
    print("Created:", path_b)

    # 3. Create stripped PNG image (no EXIF)
    img_c = Image.new("RGBA", (400, 400), color=(40, 180, 120, 255))
    path_c = os.path.join(SAMPLES_DIR, "sample_stripped.png")
    img_c.save(path_c, "png")
    print("Created:", path_c)


if __name__ == "__main__":
    create_samples()
