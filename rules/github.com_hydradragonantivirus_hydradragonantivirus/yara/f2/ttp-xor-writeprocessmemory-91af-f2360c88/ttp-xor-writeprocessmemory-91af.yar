rule TTP_XOR_WriteProcessMemory_91af {
  strings:
    $key_91af = { c6 dd [2] f4 ff [2] f2 ca [2] dc ca [2] e3 d6 }

  condition:
    any of them
}