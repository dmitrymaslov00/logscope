from pathlib import Path
from logscope.models import Rule
import yaml



class RuleError(ValueError):
    pass


def load_rule(path: Path) -> Rule:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            try:
                config = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise RuleError(f'{path}: invalid YAML: {e}') from e
            
            if not isinstance(config, dict):
                raise RuleError(f'{path}: rule must be a mapping')

            if 'id' not in config:
                raise RuleError(f'{path}: missing field "id"')
            if not isinstance(config.get('id'), str):
                raise RuleError(f'{path}: "id" must be a string')
            if not config['id'].strip(): 
                raise RuleError(f'{path}: "id" must not be empty')

            if 'event_type' not in config:
                raise RuleError(f'{path}: missing field "event_type"')
            if not isinstance(config.get('event_type'), str):
                raise RuleError(f'{path}: "event_type" must be a string')
            if not config['event_type'].strip(): 
                raise RuleError(f'{path}: "event_type" must not be empty')

            if 'threshold' not in config:
                raise RuleError(f'{path}: missing field "threshold"')
            if isinstance(config.get('threshold'), bool) or not isinstance(config.get('threshold'), int):
                raise RuleError(f'{path}: "threshold" must be an integer')
            if config.get('threshold') <= 0:
                raise RuleError(f'{path}: "threshold" must be greater than 0')

            if 'window_seconds' not in config:
                raise RuleError(f'{path}: missing field "window_seconds"')
            if isinstance(config.get('window_seconds'), bool) or not isinstance(config.get('window_seconds'), int):
                raise RuleError(f'{path}: "window_seconds" must be an integer')
            if config.get('window_seconds') <= 0:
                raise RuleError(f'{path}: "window_seconds" must be greater than 0')
            
            if 'title' in config:
                if not isinstance(config.get('title'), str):
                    raise RuleError(f'{path}: "title" must be a string')

            if 'description' in config:
                if not isinstance(config.get('description'), str):
                    raise RuleError(f'{path}: "description" must be a string')

            return Rule(
                id = config.get('id'),
                event_type = config.get('event_type'),
                threshold = config.get('threshold'),
                window_seconds = config.get('window_seconds'),
                title = config.get('title', ''),
                description = config.get('description', '')
            )
        
            
    except OSError as e:
        raise RuleError(f'{path}: cannot read file ({e})') from e