rule TTP_XOR_WriteProcessMemory_69af {
  strings:
    $key_69af = { 3e dd [2] 0c ff [2] 0a ca [2] 24 ca [2] 1b d6 }

  condition:
    any of them
}