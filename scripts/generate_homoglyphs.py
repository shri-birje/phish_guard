# scripts/generate_homoglyphs.py
import itertools

# Define letter substitutions (homoglyphs & lookalikes)
substitutions = {
    'a': ['a', 'а', 'α'],   # latin a, cyrillic a, greek alpha
    'o': ['o', '0', 'о'],   # latin o, zero, cyrillic o
    'e': ['e', 'е'],        # latin e, cyrillic e
    'i': ['i', '1', 'і'],   # latin i, one, cyrillic i
    'l': ['l', '1', 'I'],   # lowercase l, one, capital I
    's': ['s', '$', 'ѕ'],   # latin s, dollar, cyrillic s
    'c': ['c', 'с']         # latin c, cyrillic c
}

def variants(word, max_variants=200):
    """Generate homoglyph variations for a brand name."""
    positions = [i for i, ch in enumerate(word) if ch.lower() in substitutions]
    res = set()
    for r in range(1, min(len(positions) + 1, 4)):  # change up to 4 chars
        for combo in itertools.combinations(positions, r):
            choices = []
            for i, ch in enumerate(word):
                if i in combo:
                    choices.append(substitutions[ch.lower()])
                else:
                    choices.append([ch])
            for prod in itertools.product(*choices):
                res.add(''.join(prod))
                if len(res) >= max_variants:
                    return list(res)
    return list(res)

if __name__ == "__main__":
    brands = ['google', 'paypal', 'amazon', 'facebook']
    out = []
    for b in brands:
        for v in variants(b, max_variants=300):
            out.append(v + '.com')
    with open('data/synthetic_homoglyphs.txt', 'w', encoding='utf-8') as f:
        for x in out:
            f.write(x + '\n')
    print("✅ Generated", len(out), "synthetic homoglyph URLs.")
