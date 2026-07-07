import os
import math


def calculate_entropy(filepath):
    """Calculate Shannon Entropy of a file"""

    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) == 0:
        return 0

    entropy = 0
    byte_counts = [0] * 256

    for byte in data:
        byte_counts[byte] += 1

    for count in byte_counts:
        if count == 0:
            continue
        probability = count / len(data)
        entropy -= probability * math.log2(probability)

    return entropy


def extract_features(filepath):
    """
    Extract basic features from uploaded file.
    """

    file_size = os.path.getsize(filepath)

    extension = os.path.splitext(filepath)[1].lower()

    entropy = calculate_entropy(filepath)

    features = {
        "file_size": file_size,
        "entropy": entropy,
        "extension": extension
    }

    return features