rule TTP_XOR_WriteProcessMemory_9fed {
  strings:
    $key_9fed = { c8 9f [2] fa bd [2] fc 88 [2] d2 88 [2] ed 94 }

  condition:
    any of them
}