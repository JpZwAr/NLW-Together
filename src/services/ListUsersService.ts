import { getCustomRepository } from "typeorm"
import { UsersRepositories } from "../repositories/UsersRepositories";
import { classToPlain} from "class-transformer";

class ListUsersService {
    async execute() {
        const listUsersRepositories = getCustomRepository(UsersRepositories);

        const users = await listUsersRepositories.find();

        return classToPlain(users);
    }
}

export { ListUsersService }