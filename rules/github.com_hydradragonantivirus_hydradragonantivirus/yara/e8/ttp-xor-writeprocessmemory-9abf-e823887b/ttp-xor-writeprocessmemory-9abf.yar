rule TTP_XOR_WriteProcessMemory_9abf {
  strings:
    $key_9abf = { cd cd [2] ff ef [2] f9 da [2] d7 da [2] e8 c6 }

  condition:
    any of them
}