rule TTP_XOR_WriteProcessMemory_ce9a {
  strings:
    $key_ce9a = { 99 e8 [2] ab ca [2] ad ff [2] 83 ff [2] bc e3 }

  condition:
    any of them
}