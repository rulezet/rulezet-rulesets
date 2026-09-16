rule TTP_XOR_WriteProcessMemory_c89a {
  strings:
    $key_c89a = { 9f e8 [2] ad ca [2] ab ff [2] 85 ff [2] ba e3 }

  condition:
    any of them
}