rule FVEY_ShadowBroker_gr_gr {
   meta:
      description = "Auto-generated rule - file gr.notes"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "b2b60dce7a4cfdddbd3d3f1825f1885728956bae009de3a307342fbdeeafcb79"
      id = "c233159d-8d78-575b-b32b-21f704debfe2"
   strings:
      $s4 = "delete starting from: (root) LIST (root)" fullword ascii
   condition:
      1 of them
}