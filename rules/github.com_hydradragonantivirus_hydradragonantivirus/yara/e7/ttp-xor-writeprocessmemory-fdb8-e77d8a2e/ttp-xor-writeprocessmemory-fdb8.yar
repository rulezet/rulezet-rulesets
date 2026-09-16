rule TTP_XOR_WriteProcessMemory_fdb8 {
  strings:
    $key_fdb8 = { aa ca [2] 98 e8 [2] 9e dd [2] b0 dd [2] 8f c1 }

  condition:
    any of them
}