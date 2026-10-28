from logscope.rules.loader import load_rule, load_rules, RuleError
import pytest



def test_valid_rule_is_loaded(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: 60
    title: SSH brute force
    description: Many failed logins from one IP
    """, encoding='utf-8')

    res = load_rule(p)

    assert res.id == 'ssh_brute_force'
    assert res.event_type == 'ssh_login_failed'
    assert res.threshold == 5
    assert res.window_seconds == 60
    assert res.title == 'SSH brute force'
    assert res.description == 'Many failed logins from one IP'


def test_optional_fields_default_to_empty(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: 60
    """, encoding='utf-8')

    res = load_rule(p)

    assert res.title == ''
    assert res.description == ''


def test_missing_file_raises(tmp_path):
    p = tmp_path / 'nope.yml'

    with pytest.raises(RuleError, match='cannot read file'): 
        load_rule(p)



def test_invalid_yaml_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
        id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: 60
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='invalid YAML'):
        load_rule(p)


def test_empty_file_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='rule must be a mapping'):
        load_rule(p)


def test_top_level_list_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text('- id\n- threshold\n', encoding='utf-8')

    with pytest.raises(RuleError, match='rule must be a mapping'): 
        load_rule(p)


def test_missing_required_field_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: 60
    """, encoding='utf-8')

    with pytest.raises(RuleError, match='missing field "id"'):
        load_rule(p)

    p.write_text(
    """
    id: ssh_brute_force
    threshold: 5
    window_seconds: 60
    """, encoding='utf-8')

    with pytest.raises(RuleError, match='missing field "event_type"'):
        load_rule(p)

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    window_seconds: 60
    """, encoding='utf-8')

    with pytest.raises(RuleError, match='missing field "threshold"'):
        load_rule(p)

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 5
    """, encoding='utf-8')

    with pytest.raises(RuleError, match='missing field "window_seconds"'):
        load_rule(p)


def test_wrong_type_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: qwe
    window_seconds: 60
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"threshold" must be an integer'):
        load_rule(p)


def test_bool_threshold_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: true
    window_seconds: 60
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"threshold" must be an integer'):
        load_rule(p)


def test_bool_window_seconds_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: true
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"window_seconds" must be an integer'):
        load_rule(p)


def test_not_string_id_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: 123
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: 60
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"id" must be a string'):
        load_rule(p)


def test_not_string_event_type_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: 123
    threshold: 5
    window_seconds: 60
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"event_type" must be a string'):
        load_rule(p)


def test_empty_id_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: "   "
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: 60
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"id" must not be empty'):
        load_rule(p)


def test_empty_event_type_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: "   "
    threshold: 5
    window_seconds: 60
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"event_type" must not be empty'):
        load_rule(p)


def test_zero_or_negative_threshold_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 0
    window_seconds: 60
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"threshold" must be greater than 0'):
        load_rule(p)

    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: -1
    window_seconds: 60
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"threshold" must be greater than 0'):
        load_rule(p)


def test_zero_or_negative_window_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: 0
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"window_seconds" must be greater than 0'):
        load_rule(p)

    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: -1
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"window_seconds" must be greater than 0'):
        load_rule(p)


def test_not_string_title_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: 60
    title: 123
    description: Many failed logins from one IP
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"title" must be a string'):
        load_rule(p)


def test_not_string_description_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: 60
    title: SSH brute force
    description: 123
    """, encoding='utf-8')


    with pytest.raises(RuleError, match='"description" must be a string'):
        load_rule(p)


def test_load_rules_empty_directory_returns_empty_list(tmp_path):
    res = load_rules(tmp_path)

    assert res == []


def test_load_rules_missing_directory_raises(tmp_path):
    p = tmp_path / 'nope'

    with pytest.raises(RuleError, match='not a directory'):
        load_rules(p)


def test_load_rules_loads_all_files(tmp_path):
    a = tmp_path / 'a.yml'
    b = tmp_path / 'b.yml'

    a.write_text(
        """
        id: rule_a
        event_type: ssh_login_failed
        threshold: 5
        window_seconds: 60
        """, encoding='utf-8'
    )

    b.write_text(
        """
        id: rule_b
        event_type: ssh_login_failed
        threshold: 5
        window_seconds: 60
        """, encoding='utf-8'
    )


    res = load_rules(tmp_path)

    assert len(res) == 2
    assert res[0].id == 'rule_a'
    assert res[1].id == 'rule_b'


def test_load_rules_duplicate_id_raises(tmp_path):
    a = tmp_path / 'a.yml'
    b = tmp_path / 'b.yml'

    a.write_text(
        """
        id: rule_a
        event_type: ssh_login_failed
        threshold: 5
        window_seconds: 60
        """, encoding='utf-8'
    )

    b.write_text(
        """
        id: rule_a
        event_type: ssh_login_failed
        threshold: 5
        window_seconds: 60
        """, encoding='utf-8'
    )


    with pytest.raises(RuleError, match='a.yml.*b.yml'):
        load_rules(tmp_path)


def test_load_rules_invalid_file_raises(tmp_path):
    p = tmp_path / 'rule.yml'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 0
    window_seconds: 60
    """, encoding='utf-8')

    with pytest.raises(RuleError, match='"threshold" must be greater than 0'):
        load_rules(tmp_path)


def test_load_rules_ignores_non_yaml_files(tmp_path):
    p = tmp_path / 'rule.yml'
    n = tmp_path / 'note.txt'

    p.write_text(
    """
    id: ssh_brute_force
    event_type: ssh_login_failed
    threshold: 5
    window_seconds: 60
    """, encoding='utf-8')

    n.write_text('this is: [not a rule', encoding='utf-8')

    res = load_rules(tmp_path)

    assert len(res) == 1