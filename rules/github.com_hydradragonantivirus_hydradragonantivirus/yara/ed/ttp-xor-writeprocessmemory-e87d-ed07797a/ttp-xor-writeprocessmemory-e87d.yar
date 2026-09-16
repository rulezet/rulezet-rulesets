rule TTP_XOR_WriteProcessMemory_e87d {
  strings:
    $key_e87d = { bf 0f [2] 8d 2d [2] 8b 18 [2] a5 18 [2] 9a 04 }

  condition:
    any of them
}