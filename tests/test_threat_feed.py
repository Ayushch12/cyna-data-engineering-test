from ingestion.load_threat_feed import load_ipsum_feed
import tempfile
import os


def test_load_ipsum_feed_basic():
    content = "1.2.3.4 5\n8.8.8.8 10\n"

    with tempfile.NamedTemporaryFile(delete=False, mode="w") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    df = load_ipsum_feed(tmp_path)

    os.remove(tmp_path)

    assert len(df) == 2
    assert df.iloc[0]["ip"] == "1.2.3.4"
    assert df.iloc[0]["confidence_level"] == 5
