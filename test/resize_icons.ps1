Add-Type -AssemblyName System.Drawing

$sourcePath = "d:\STUFF\AI Phishing Detection\extension\icons\icon128.png"
$tempPath   = "d:\STUFF\AI Phishing Detection\extension\icons\icon_temp_backup.png"

if (Test-Path $sourcePath) {
    # Backup original logo
    Copy-Item $sourcePath $tempPath -Force
    
    $sizes = @(16, 32, 48, 128)
    foreach ($size in $sizes) {
        $srcImg = [System.Drawing.Image]::FromFile($tempPath)
        $destImg = [System.Drawing.Bitmap]::new($size, $size)
        $g = [System.Drawing.Graphics]::FromImage($destImg)
        
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        
        $g.DrawImage($srcImg, 0, 0, $size, $size)
        
        $outputPath = "d:\STUFF\AI Phishing Detection\extension\icons\icon$($size).png"
        
        # If output file exists, delete it first to avoid GDI+ lock clashes
        if (Test-Path $outputPath) {
            # Note: We are loading from $tempPath, so we can safely delete $outputPath even if it is icon128.png
            if ($outputPath -ne $tempPath) {
                Remove-Item $outputPath -Force
            }
        }
        
        $destImg.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
        
        $g.Dispose()
        $destImg.Dispose()
        $srcImg.Dispose()
        Write-Host "Resized successfully: $($size)x$($size) -> $outputPath"
    }
    
    # Remove backup
    if (Test-Path $tempPath) {
        Remove-Item $tempPath -Force
    }
} else {
    Write-Error "Source icon not found at: $sourcePath"
}
