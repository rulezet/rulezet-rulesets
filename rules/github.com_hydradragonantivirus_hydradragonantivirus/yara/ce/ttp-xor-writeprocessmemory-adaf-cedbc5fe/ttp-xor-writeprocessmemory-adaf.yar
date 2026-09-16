rule TTP_XOR_WriteProcessMemory_adaf {
  strings:
    $key_adaf = { fa dd [2] c8 ff [2] ce ca [2] e0 ca [2] df d6 }

  condition:
    any of them
}