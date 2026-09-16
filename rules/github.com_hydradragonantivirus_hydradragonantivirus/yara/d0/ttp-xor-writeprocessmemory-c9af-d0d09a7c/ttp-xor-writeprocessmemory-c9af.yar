rule TTP_XOR_WriteProcessMemory_c9af {
  strings:
    $key_c9af = { 9e dd [2] ac ff [2] aa ca [2] 84 ca [2] bb d6 }

  condition:
    any of them
}