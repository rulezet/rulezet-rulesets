rule sig_20160321_82daaa4134e50766654942ce991524c6 {
  meta:
    description = "datamaliciousorder - file 20160321_82daaa4134e50766654942ce991524c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2b606516ccadd9149378c10db1b8651e3672c64a1d72fa981d29962474a44af"

  strings:
    $s1  = "sixth((\"phosphate\",\"furnishings\",\"proverbial\",\"htt\")+(\"gasoline\",\"initial\",\"references\",\"quieter\",\"p://ci\")+(" ascii
    $s2  = "th > 2 && (token = tokens[0]).type === \\\"ID\\\" && support.getById && context.nodeType === 9 && documentIsHTML && Expr.relativ" ascii
    $s3  = "   NrobOi = \" Reduce context if the leading compound selector is an ID tokens = match[0] = match[0].slice( 0 ); if ( tokens.len" ascii
    $s4  = "    azyJIKIBEtu = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Str" ascii
    $s5  = "|Function} selector A selector or a pre-compiled * selector function built with Sizzle.compile * @param {Element} context * @par" ascii
    $s6  = "context, results, seed ) { var i, tokens, token, type, find, compiled = typeof selector === \\\"function\\\" && selector, match " ascii
    $s7  = "eed && tokenize( (selector = compiled.selector || selector) );\";" fullword ascii
    $s8  = "unlike = ((\"ridge\", \"gangbang\", \"bvPVQcP\", \"terminals\", \"pnEIhKpPncxD\") + \"QtpWall\").vegetation();" fullword ascii
    $s9  = "lXOXRtM = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s10 = "String.prototype.vegetation = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "lXOXRtM = \"} Override manipulation of globals by nested matchers if ( outermost ) { dirruns = dirrunsUnique; outermostContext =" ascii
    $s12 = "length > 0 && ( matchedCount + setMatchers.length ) > 1 ) {\";" fullword ascii
    $s13 = "NqTRLU = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s14 = "        uTeOmABdFkP = \"}compile = Sizzle.compile = function( selector, match /* Internal Use Only */ ) { var i, setMatchers = [" ascii
    $s15 = "am {Array} [results] * @param {Array} [seed] A set of elements to match against */ select = Sizzle.select = function( selector, " ascii
    $s16 = "l verify ancestry, so step up a level } else if ( compiled ) { context = context.parentNode; \";" fullword ascii
    $s17 = ", elementMatchers = [], cached = compilerCache[ selector + \\\" \\\" ];\";" fullword ascii
    $s18 = "NqTRLU = \" Seedless set matches succeeding multiple successful matchers stipulate sorting if ( outermost && !seed && setMatched" ascii
    $s19 = "        Mvbaj[rzEnmWt[attendingI + 1]](agreements, 1, \"rAIvAYJmFym\" === \"ITvmAbGz\"); HqbvVQNQ = \" Precompiled matchers will" ascii
    $s20 = "    azyJIKIBEtu = \"/** * A low-level selection function that works with Sizzle\\\"s compiled * selector functions * @param {Str" ascii

  condition:
    uint16(0) == 0x7248 and
    8 of them
}