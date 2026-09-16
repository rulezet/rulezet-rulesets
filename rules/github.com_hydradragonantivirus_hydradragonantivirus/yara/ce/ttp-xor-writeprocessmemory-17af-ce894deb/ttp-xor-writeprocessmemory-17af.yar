rule TTP_XOR_WriteProcessMemory_17af {
  strings:
    $key_17af = { 40 dd [2] 72 ff [2] 74 ca [2] 5a ca [2] 65 d6 }

  condition:
    any of them
}