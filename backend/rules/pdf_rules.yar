/*
   pdf_rules.yar
   -------------
   YARA signature rules for detecting suspicious structural elements
   and potential malware patterns in PDF files.

   Author: Khushali (23DIT007)
*/

rule Suspicious_PDF_JavaScript {
    meta:
        description = "Detects obfuscated or embedded JavaScript streams in PDF"
        severity = "High"
    strings:
        $js1 = "/JS" ascii wide
        $js2 = "/JavaScript" ascii wide
        $eval = "eval(" ascii wide
        $unescape = "unescape(" ascii wide
    condition:
        ($js1 or $js2) and ($eval or $unescape)
}

rule Suspicious_PDF_AutoLaunch {
    meta:
        description = "Detects auto-execution triggers or external program launch commands"
        severity = "Critical"
    strings:
        $launch = "/Launch" ascii wide
        $openaction = "/OpenAction" ascii wide
        $cmd = "cmd.exe" ascii wide nocase
        $powershell = "powershell" ascii wide nocase
    condition:
        ($launch or $openaction) or ($cmd or $powershell)
}

rule Suspicious_Embedded_Binary {
    meta:
        description = "Detects embedded executable payloads (MZ header) inside PDF streams"
        severity = "Critical"
    strings:
        $mz = "TVqQAAMAAAAEAAAA" ascii wide // Base64 encoded MZ executable header
        $raw_mz = { 4D 5A 90 00 }        // Raw MZ header bytes
    condition:
        $mz or $raw_mz
}
