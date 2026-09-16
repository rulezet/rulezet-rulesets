rule TTP_XOR_WriteProcessMemory_99af {
  strings:
    $key_99af = { ce dd [2] fc ff [2] fa ca [2] d4 ca [2] eb d6 }

  condition:
    any of them
}