import pathlib
import tempfile

import pytest

from vulnforge.app import FLAGS, create_app
from vulnforge.config import Config
from vulnforge.db import connect
from vulnforge.lessons import base as lessons
from vulnforge.sandbox import build_sandbox


@pytest.fixture
def config():
    return Config(sandbox_dir=tempfile.mkdtemp())


@pytest.fixture
def app(config):
    return create_app(config)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def ctx():
    lessons.load_all()
    root = pathlib.Path(tempfile.mkdtemp())
    sandbox = build_sandbox(root / "files", FLAGS)
    db = connect(root, FLAGS)
    return lessons.LessonContext(db=db, sandbox=sandbox, session={}, flags=FLAGS)
