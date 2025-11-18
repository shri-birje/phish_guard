"""
Legacy helper that now delegates to the upgraded training pipeline.
Run this script if you prefer the older entry point; it simply invokes train_model.main().
"""

from train_model import main

if __name__ == "__main__":
    main()
