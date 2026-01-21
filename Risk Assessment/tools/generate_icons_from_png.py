from __future__ import annotations

from pathlib import Path

from PIL import Image


def main() -> None:
    src = Path(r"v:/Risk Assessment/static/icons/app-icon.png")
    out_dir = Path(r"v:/Risk Assessment/static/icons")

    if not src.exists():
        raise SystemExit(f"Source image not found: {src}")

    out_dir.mkdir(parents=True, exist_ok=True)

    img = Image.open(src).convert("RGBA")
    print("Source:", src)
    print("Size:", img.size)

    def save_png(size: int, name: str) -> None:
        out = out_dir / name
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(out, format="PNG", optimize=True)
        print("Wrote", out, "=>", size)

    # Favicons
    save_png(16, "favicon-16.png")
    save_png(32, "favicon-32.png")

    # Apple touch
    save_png(180, "apple-touch-icon.png")

    # PWA icons
    save_png(192, "icon-192.png")
    save_png(512, "icon-512.png")

    # Multi-size ICO
    ico_path = out_dir / "favicon.ico"
    img_ico = img.resize((256, 256), Image.Resampling.LANCZOS)
    img_ico.save(
        ico_path,
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )
    print("Wrote", ico_path)


if __name__ == "__main__":
    main()
