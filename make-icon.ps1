# Extracts the gear icon (shell32.dll,314) into gear.ico at multiple sizes so
# the resource compiler can embed it. Run automatically by build.bat; the
# resulting gear.ico is a build artifact, not committed.
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class IconExtract {
  [DllImport("user32.dll")]
  public static extern int PrivateExtractIcons(string path, int index, int cx, int cy, IntPtr[] hicon, IntPtr[] id, int count, int flags);
}
"@
$src   = "$env:SystemRoot\System32\shell32.dll"
$index = 314
$out   = Join-Path $PSScriptRoot "gear.ico"
$sizes = @(16, 24, 32, 48, 64, 128, 256)

$imgs = @()
foreach ($s in $sizes) {
  $h = New-Object IntPtr[] 1
  $n = [IconExtract]::PrivateExtractIcons($src, $index, $s, $s, $h, $null, 1, 0)
  if ($n -lt 1 -or $h[0] -eq [IntPtr]::Zero) { continue }
  $ic = [System.Drawing.Icon]::FromHandle($h[0])
  $bmp = $ic.ToBitmap()
  $ms = New-Object System.IO.MemoryStream
  $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
  $imgs += [pscustomobject]@{ Size = $s; Data = $ms.ToArray() }
  $bmp.Dispose()
}
if ($imgs.Count -eq 0) { throw "Could not extract icon $index from $src" }

$fs = [System.IO.File]::Create($out)
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$imgs.Count)   # ICONDIR
$offset = 6 + 16 * $imgs.Count
foreach ($im in $imgs) {
  $wh = $im.Size; if ($wh -ge 256) { $wh = 0 }
  $bw.Write([Byte]$wh); $bw.Write([Byte]$wh); $bw.Write([Byte]0); $bw.Write([Byte]0)
  $bw.Write([UInt16]1); $bw.Write([UInt16]32)
  $bw.Write([UInt32]$im.Data.Length); $bw.Write([UInt32]$offset)
  $offset += $im.Data.Length
}
foreach ($im in $imgs) { $bw.Write($im.Data) }
$bw.Flush(); $fs.Close()
Write-Host ("[+] gear.ico: sizes=" + ($imgs.Size -join ",") + " bytes=" + ((Get-Item $out).Length))
