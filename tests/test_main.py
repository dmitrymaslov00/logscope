from logscope.__main__ import main



def test_main_accepts_valid_rules(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / 'rule.yml').write_text(
        """
        id: ssh_brute_force
        event_type: ssh_login_failed
        threshold: 5
        window_seconds: 60
        title: SSH brute force
        description: Many failed logins from one IP
        """, encoding='utf-8'
    )

    result = main([
        "--log", str(tmp_path / "auth.log"),
        "--rules", str(rules_dir),
        "--db", str(tmp_path / "test.db"),
        "--year", "2026",
    ])

    assert result == 0


def test_main_rejects_invalid_rule(tmp_path, capsys):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / 'rule.yml').write_text(
        """
        id: ssh_brute_force
        event_type: ssh_login_failed
        threshold: 0
        window_seconds: 60
        title: SSH brute force
        description: Many failed logins from one IP
        """, encoding='utf-8'
    )

    result = main([
        "--log", str(tmp_path / "auth.log"),
        "--rules", str(rules_dir),
        "--db", str(tmp_path / "test.db"),
        "--year", "2026",
    ])

    captured = capsys.readouterr()

    assert result == 1
    assert 'threshold' in captured.err
    assert captured.out == ''