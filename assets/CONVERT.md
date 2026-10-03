# Converting Logo Assets

## Files

- `logo.svg` - Main logo (128x128) for README and documentation
- `icon.svg` - Simplified icon (64x64) for application icon

## Convert to PNG

### Using Inkscape (recommended)
```bash
inkscape logo.svg -w 128 -h 128 -o logo.png
inkscape icon.svg -w 256 -h 256 -o icon-256.png
inkscape icon.svg -w 64 -h 64 -o icon-64.png
inkscape icon.svg -w 32 -h 32 -o icon-32.png
inkscape icon.svg -w 16 -h 16 -o icon-16.png
```

### Using ImageMagick
```bash
magick convert logo.svg -resize 128x128 logo.png
magick convert icon.svg -resize 256x256 icon-256.png
```

### Using online tools
- [SVG to PNG Converter](https://svgtopng.com/)
- [CloudConvert](https://cloudconvert.com/svg-to-png)

## Create Windows ICO

### Using ImageMagick
```bash
magick convert icon.svg -define icon:auto-resize=256,128,64,48,32,16 icon.ico
```

### Using GIMP
1. Open icon.svg
2. Scale to 256x256
3. Export as icon.ico
4. Select "Compressed (PNG)" and include sizes: 256, 48, 32, 16

## Embed Icon in Executable

1. Create `icon.rc`:
```
IDI_ICON1 ICON "icon.ico"
```

2. Add to CMakeLists.txt:
```cmake
if(WIN32)
    set(APP_ICON_RESOURCE "${CMAKE_SOURCE_DIR}/assets/icon.rc")
    target_sources(DriverSight PRIVATE ${APP_ICON_RESOURCE})
endif()
```

3. Rebuild the project

## Color Palette

| Color | Hex | Usage |
|-------|-----|-------|
| Dark Blue BG | #1a1a2e | Background |
| Cyan | #00d4ff | Primary accent |
| Blue | #0066ff | Secondary |
| Green | #00ff88 | Circuit traces |
| White | #ffffff | Highlights |
