rule TTP_XOR_WriteProcessMemory_bd9a {
  strings:
    $key_bd9a = { ea e8 [2] d8 ca [2] de ff [2] f0 ff [2] cf e3 }

  condition:
    any of them
}