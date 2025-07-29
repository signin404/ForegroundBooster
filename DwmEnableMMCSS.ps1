$signature = @'
[DllImport("dwmapi.dll", SetLastError=true)]
public static extern int DwmEnableMMCSS(bool enable);
'@
$dwmapi = Add-Type -MemberDefinition $signature -Name "DwmApi" -Namespace "API" -PassThru

while ($true) {
    $result = $dwmapi::DwmEnableMMCSS($true)
    Start-Sleep -Seconds 60
}
