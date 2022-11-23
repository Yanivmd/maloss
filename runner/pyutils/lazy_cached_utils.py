import functools
from pathlib import Path
from typing import List, Tuple, Type

from dill import load as dill_load, dumps as dill_dumps
from jsonpickle import decode as jp_load, encode as jp_dump


def lazy_cached_runner(object_unique_identifier: Tuple[str], expected_exceptions_list: List[Type[Exception]],
                       json_serialization: bool = False):
    error_prefix = "ERR4R_"

    # these are the first steps of our FS storage layer
    expected_path = None
    object_is_cached = False
    cached_object_is_exception = False
    for object_part_index, object_path_part in enumerate(object_unique_identifier):
        if expected_path is None:
            expected_path = Path(object_path_part)
        else:
            expected_path = expected_path.joinpath(object_path_part)

    expected_exception_path = expected_path.parent.joinpath(f"{error_prefix}{expected_path.name}")
    if expected_path.exists():
        object_is_cached = True
        used_path = expected_path
    elif expected_exception_path.exists():
        object_is_cached = True
        cached_object_is_exception = True
        used_path = expected_exception_path

    def lazy_decorator(user_function):
        @functools.wraps(user_function)
        def wrapper(*args, **kwargs):
            nonlocal cached_object_is_exception
            if object_is_cached:
                if json_serialization:
                    cached_object = jp_load(used_path.read_text())
                else:
                    cached_object = dill_load(used_path.open("rb"))
            else:
                try:
                    cached_object = user_function(*args, **kwargs)
                except Exception as e:
                    cached_object = e
                    cached_object_is_exception = True
                    if expected_exceptions_list is None:
                        exception_dump = True
                    else:
                        exception_dump = any(map(lambda x: isinstance(e, x), expected_exceptions_list))
                    if exception_dump:
                        out_path = expected_exception_path
                    else:
                        out_path = None
                else:
                    out_path = expected_path

                if out_path is not None:
                    if json_serialization:
                        out_path.write_text(jp_dump(cached_object, indent=True))
                    else:
                        out_path.write_bytes(dill_dumps(cached_object))

            if cached_object_is_exception:
                raise cached_object
            else:
                return cached_object

        wrapper.cached_object_is_exception = cached_object_is_exception
        wrapper.object_is_cached = object_is_cached
        return wrapper

    #lazy_decorator.object_is_cached = object_is_cached
    return lazy_decorator


if __name__ == '__main__':
    import tempfile

    tmp_f_path = Path(tempfile.mktemp("tester_exception"))


    @lazy_cached_runner(tmp_f_path.parts, [ValueError])
    def tester_exception_1(throw: bool, throw_known: bool):
        if throw:
            if throw_known:
                raise ValueError("testing")
            else:
                raise NotImplementedError()
        else:
            return {'DONE': 1}

    try:
        assert(not tester_exception_1.object_is_cached)
        assert (not tester_exception_1.cached_object_is_exception)
        tester_exception_1(True, False)
    except Exception as e:
        assert isinstance(e, NotImplementedError)

    @lazy_cached_runner(tmp_f_path.parts, [ValueError])
    def tester_exception_2(throw: bool, throw_known: bool):
        if throw:
            if throw_known:
                raise ValueError("testing")
            else:
                raise NotImplementedError()
        else:
            return {'DONE': 1}

    try:
        assert (not tester_exception_2.object_is_cached)
        assert (not tester_exception_2.cached_object_is_exception)
        tester_exception_2(True, True)
    except Exception as e:
        assert isinstance(e, ValueError)

    @lazy_cached_runner(tmp_f_path.parts, [ValueError])
    def tester_exception_3(throw: bool, throw_known: bool):
        raise hell # this should never be reached.

    try:
        assert tester_exception_3.object_is_cached
        assert tester_exception_3.cached_object_is_exception
        tester_exception_3(False, False)
    except Exception as e:
        assert isinstance(e, ValueError)

    tmp_f_path_good = Path(tempfile.mktemp("tester_good"))


    @lazy_cached_runner(tmp_f_path_good.parts, [ValueError])
    def tester_good_1(throw: bool, throw_known: bool):
        if throw:
            if throw_known:
                raise ValueError("testing")
            else:
                raise NotImplementedError()
        else:
            return {'DONE': 1}

    try:
        tester_good_1(False, False)
    except Exception as e:
        raise hell


    @lazy_cached_runner(tmp_f_path_good.parts, [ValueError])
    def tester_good_2(throw: bool, throw_known: bool):
        raise hell # this should never be reached.

    try:
        tester_good_2(False, False)
    except Exception as e:
        raise hell



