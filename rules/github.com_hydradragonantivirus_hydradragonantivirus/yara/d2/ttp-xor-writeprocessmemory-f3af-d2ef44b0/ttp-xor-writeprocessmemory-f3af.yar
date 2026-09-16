rule TTP_XOR_WriteProcessMemory_f3af {
  strings:
    $key_f3af = { a4 dd [2] 96 ff [2] 90 ca [2] be ca [2] 81 d6 }

  condition:
    any of them
}