rule DELIVRTO_SUSP_Onenote_Win_Script_Encoding_Feb23: FILE {
  meta:
    description = "Presence of Windows Script Encoding Header in a OneNote file with embedded files"
    author      = "delivr.to"
    id          = "95cd5ce0-07b3-5503-ad6f-944206bd4fb6"
    date        = "2023-02-19"
    modified    = "2023-02-19"
    reference   = "https://github.com/delivr-to/detections"
    source_url  = "https://github.com/delivr-to/detections/blob/d2dcf7e9566e39655994aa0c5f8fb7a94cae2984/yara-rules/onenote_windows_script_encoding_file.yar#L1-L22"
    license_url = "N/A"
    logic_hash  = "b7068f551b3665358f461a076c2d46c82db558d7fa4acb7d3c9c5c2afce31253"
    score       = 60
    quality     = 78
    tags        = "FILE"

  strings:
    $one  = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
    $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }
    $wse  = "#@~^"

  condition:
    filesize < 5MB and ($one at 0) and $fdso and $wse
}