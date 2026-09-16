rule TTP_XOR_WriteProcessMemory_ad8d {
  strings:
    $key_ad8d = { fa ff [2] c8 dd [2] ce e8 [2] e0 e8 [2] df f4 }

  condition:
    any of them
}